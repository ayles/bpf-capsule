// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-capsule-ld: the BPF Capsule linker, and the core of the toolchain.
//
//   bpf-capsule-ld --kernel 6.9 -o program.o guest.bc [more.bc ...]
//
// Takes LLVM bitcode/IR produced by bpf-capsule-cc (or rustc, or any clang
// with -emit-llvm), links it into one module together with the Capsule
// runtime, runs the whole-program capsule pipeline, and emits a
// libbpf-loadable BPF ELF. Internally this subsumes llvm-link, opt, llc and
// llvm-objcopy from the reference pipeline; the passes are linked statically,
// so there is no plugin, no tool-version matching, and no PIC relocation trap.
//
// The runtime rule: the Capsule runtime (src/runtime/guest/bpf_capsule.c) is
// ordinary user code — compile it with bpf-capsule-cc like any other source
// and link its bitcode here. The linker only verifies it is present and
// says exactly that when it is not.
#include "common.h"
#include "registry.h"

#include "runtime_symbols.h"

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/DiagnosticInfo.h>
#include <llvm/IR/DiagnosticPrinter.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Object/Archive.h>
#include <llvm/Object/Binary.h>
#include <llvm/ObjCopy/CommonConfig.h>
#include <llvm/ObjCopy/ConfigManager.h>
#include <llvm/ObjCopy/ObjCopy.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/TargetParser/Triple.h>

#include <string>
#include <vector>

using namespace llvm;

namespace {

cl::OptionCategory LinkerCategory("bpf-capsule-ld options");

cl::list<std::string> InputFilenames(cl::Positional, cl::desc("<input .bc/.ll files>"), cl::OneOrMore, cl::cat(LinkerCategory));
cl::opt<std::string> OutputFilename("o", cl::desc("Output BPF object"), cl::value_desc("file"), cl::Required, cl::cat(LinkerCategory));
// Kernel and FiberStack register and validate the public options. Their parsed
// values are intentionally read by the pre-scan below, before LLVM parses the
// full command line, because they determine flags injected into that parse.
cl::opt<std::string> Kernel(
    "kernel", cl::desc("Oldest Linux kernel the object must load on (major.minor, default 6.9)"), cl::init("6.9"), cl::cat(LinkerCategory));
cl::opt<unsigned> FiberStack(
    "fiber-stack", cl::desc("Bytes in each Capsule fiber stack (power of two, default 262144)"), cl::init(262144), cl::cat(LinkerCategory));
cl::opt<bool> EmitLlvm("emit-llvm", cl::desc("Stop after the capsule pipeline and emit bitcode (debugging)"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> EmitAssembly("emit-asm", cl::desc("Stop after code generation and emit BPF assembly (debugging)"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> SaveTemps("save-temps", cl::desc("Keep <output>.linked.bc and <output>.capsule.bc beside the output"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<std::string> PipelineOverride(
    "passes", cl::desc("Replace the capsule pipeline with this opt-style pass string (experiments)"), cl::init(""), cl::cat(LinkerCategory));
cl::opt<bool> BigEndian("bpfeb", cl::desc("Emit big-endian BPF"), cl::init(false), cl::cat(LinkerCategory));

[[noreturn]] void fail(const Twine& message) {
    WithColor::error(errs(), "bpf-capsule-ld") << message << "\n";
    exit(1);
}

// This tool is the ONLY place a kernel version exists. It is converted, right
// here, into the two statements the rest of the toolchain understands: which
// passes the pipeline contains, and which preprocessor features
// bpf-capsule-cc defines for the C sources. The pass library itself carries
// no version and no feature flags.
struct KernelVersion {
    unsigned Major = 0;
    unsigned Minor = 0;
    friend auto operator<=>(const KernelVersion&, const KernelVersion&) = default;
};

KernelVersion parseKernel(StringRef text) {
    KernelVersion version;
    auto [majorText, minorText] = text.split('.');
    if (majorText.getAsInteger(10, version.Major) || minorText.getAsInteger(10, version.Minor) || version.Minor >= 1000 || version < KernelVersion{5, 15}) {
        fail("--kernel must be a Linux version of 5.15 or newer, got '" + text + "'");
    }
    return version;
}

// The whole-program capsule pipeline. This order is the compiler pipeline
// ABI: domains are computed twice — once when the boundary is lowered and
// again after default<O2> reshapes the call graph — the suspend-barrier
// fence spans exactly the O2 stage, and the second i128 pass catches
// operations O2 introduces. Target capabilities appear as composition: a
// kernel whose verifier accepts sign-extending arena loads simply does not
// get bpf-lower-arena-sext.
std::string capsulePipeline(KernelVersion kernel) {
    std::string pipeline = "bpf-expand-varargs,bpf-expand-sret,"
                           "bpf-lower-capsule-call,bpf-capsule-domains,bpf-lower-capsule-exit,bpf-add-suspend-barriers,"
                           "function(bpf-validate-atomics),bpf-expand-i128,bpf-soft-float,";
    if (kernel < KernelVersion{6, 6}) {
        pipeline += "bpf-lower-sdiv,";
    }
    pipeline +=
        // Even with vectorization disabled in PipelineTuningOptions, an
        // explicitly parsed default<O2> may still run target-independent
        // vector combines. BPF has no vector registers; scalarize the complete
        // post-O2 IR before any Capsule lowering or SelectionDAG sees it.
        "function(bpf-inline-policy),default<O2>,function(scalarizer<load-store>),bpf-expand-i128,"
        "function(bpf-expand-mem),bpf-internalize,globaldce,function(bpf-validate-no-float),"
        "function(bpf-normalize-irreducible,fix-irreducible),bpf-capsule-domains,bpf-remove-suspend-barriers,";
    if (kernel < KernelVersion{6, 9}) {
        pipeline += kernel < KernelVersion{6, 6} ? "bpf-stackify-fixed-v3," : "bpf-stackify-fixed,";
    } else {
        pipeline += kernel >= KernelVersion{7, 1} ? "bpf-stackify-direct," : "bpf-stackify,";
    }
    pipeline +=
        // Stackify introduces the entry-to-driver call after whole-program O2.
        // The driver source marks only its top wrapper alwaysinline; use LLVM's
        // ordinary attribute-driven pass to fold that wrapper and GlobalDCE to
        // discard it. Stackify's conservative single-use inlining has already
        // run; this stage does not revisit application functions.
        "always-inline,globaldce,function(early-cse,gvn,adce),function(bpf-normalize-irreducible,fix-irreducible),"
        "function(bpf-define-undef),";
    if (kernel < KernelVersion{6, 9}) {
        pipeline += "function(bpf-scalarize-agg),bpf-memory-fixed,";
    } else {
        pipeline += "bpf-memory-arena,";
    }
    pipeline += "function(bpf-infer-as),";
    // Before Linux 7.0 the verifier rejects BPF_MEMSX from PTR_TO_ARENA on
    // every architecture; 7.0 made this conditional on the target JIT.
    if (kernel >= KernelVersion{6, 9} && kernel < KernelVersion{7, 0}) {
        pipeline += "function(bpf-lower-arena-sext),";
    }
    pipeline += "function(bpf-finalize-atomic-load-store),function(bpf-split-shift63),";
    // Instruction-array dispatch needs the kernel verifier, libbpf
    // relocation and target JIT landing-pad support as one capability. The
    // conservative portable floor is 7.1; older targets keep compare trees.
    if (kernel < KernelVersion{7, 1}) {
        pipeline += "function(bpf-no-jump-tables),";
    }
    pipeline += "bpf-sanitize-btf";
    return pipeline;
}

bool definesRuntime(const Module& module) {
    // A symbol the runtime source genuinely defines (several guest-header
    // names are extern markers the compiler resolves, not definitions).
    const Function* function = module.getFunction(bpf::sym::RuntimeProbe);
    return function && !function->isDeclaration();
}

} // namespace

int main(int argc, char** argv) {
    InitLLVM init(argc, argv);
    InitializeAllTargetInfos();
    InitializeAllTargets();
    InitializeAllTargetMCs();
    InitializeAllAsmPrinters();
    InitializeAllAsmParsers();

    // The pass library's own cl::opts (every -bpf-* knob) are registered by
    // static initializers together with all of upstream LLVM's, so opt/llc
    // experiment flags work here unchanged. Policy flags the reference
    // pipeline always set are injected, then everything parses in one pass.
    // --kernel and --fiber-stack are pre-scanned because injected flag values
    // depend on them.
    KernelVersion version{6, 9};
    unsigned fiberStack = 262144;
    for (int i = 1; i < argc; ++i) {
        StringRef arg(argv[i]);
        if (arg.consume_front("--kernel=") || arg.consume_front("-kernel=")) {
            version = parseKernel(arg);
        } else if ((arg == "--kernel" || arg == "-kernel") && i + 1 < argc) {
            version = parseKernel(argv[i + 1]);
        } else if (arg.consume_front("--fiber-stack=") || arg.consume_front("-fiber-stack=")) {
            (void)arg.getAsInteger(10, fiberStack);
        } else if ((arg == "--fiber-stack" || arg == "-fiber-stack") && i + 1 < argc) {
            (void)StringRef(argv[i + 1]).getAsInteger(10, fiberStack);
        }
    }
    // CPU v4 is available from Linux 6.6. Native stack capacity is deliberately
    // absent here: a post-RA machine pass derives it from the actual complete
    // call graph and selected frame sizes.
    const char* cpu = version >= KernelVersion{6, 6} ? "v4" : "v3";

    std::string fiberStackFlag = "-bpf-fiber-stack-size=" + std::to_string(fiberStack);
    std::string bpfStackFlag = "-bpf-stack-size=" + std::to_string(fiberStack);
    std::vector<const char*> args(argv, argv + argc);
    bool customPipeline = false;
    for (int i = 1; i < argc; i++) {
        if (StringRef(argv[i]).starts_with("-passes")) {
            customPipeline = true;
        }
    }
    if (!customPipeline) {
        args.push_back("-bpf-unified-spill-pipeline");
    }
    args.push_back(fiberStackFlag.c_str());
    args.push_back(bpfStackFlag.c_str());
    cl::ParseCommandLineOptions(args.size(), args.data(), "BPF Capsule linker\n");

    // ------------------------------------------------------------------ link
    LLVMContext context;
    // A pass reporting an error through the context must fail the build; the
    // default handler prints and keeps going with a half-transformed module.
    context.setDiagnosticHandlerCallBack(
        [](const DiagnosticInfo* info, void*) {
            // Optimization misses and target statistics are useful when the
            // compiler is being inspected, but they are not build warnings.
            // Large third-party programs can otherwise print megabytes of
            // vectorizer remarks even though vectorization is deliberately
            // disabled by this tool's pipeline contract.
            if (info->getSeverity() == DS_Remark && !bpf::verbose()) {
                return;
            }
            DiagnosticPrinterRawOStream printer(errs());
            errs() << "bpf-capsule-ld: ";
            info->print(printer);
            errs() << "\n";
            if (info->getSeverity() == DS_Error) {
                exit(1);
            }
        },
        nullptr);
    SMDiagnostic diagnostic;
    std::unique_ptr<Module> module;
    auto linkModule = [&](std::unique_ptr<Module> next, const Twine& what) {
        if (!module) {
            module = std::move(next);
        } else if (Linker::linkModules(*module, std::move(next))) {
            fail("cannot link " + what);
        }
    };
    auto loadAndLink = [&](const std::string& path) {
        // Static libraries are ar archives of bitcode members (llvm-ar).
        if (StringRef(path).ends_with(".a")) {
            auto buffer = MemoryBuffer::getFile(path);
            if (!buffer) {
                fail(buffer.getError().message() + ": " + path);
            }
            Error archiveError = Error::success();
            object::Archive archive((*buffer)->getMemBufferRef(), archiveError);
            if (archiveError) {
                fail("cannot read archive " + path + ": " + toString(std::move(archiveError)));
            }
            Error childError = Error::success();
            for (const object::Archive::Child& child : archive.children(childError)) {
                Expected<MemoryBufferRef> member = child.getMemoryBufferRef();
                if (!member) {
                    fail("cannot read a member of " + path + ": " + toString(member.takeError()));
                }
                Expected<std::unique_ptr<Module>> parsed = parseBitcodeFile(*member, context);
                if (!parsed) {
                    fail("archive member in " + path + " is not bitcode: " + toString(parsed.takeError()));
                }
                linkModule(std::move(*parsed), path);
            }
            if (childError) {
                fail("cannot iterate " + path + ": " + toString(std::move(childError)));
            }
            return;
        }
        std::unique_ptr<Module> next = parseIRFile(path, diagnostic, context);
        if (!next) {
            std::string text;
            raw_string_ostream stream(text);
            diagnostic.print("bpf-capsule-ld", stream);
            fail(stream.str());
        }
        linkModule(std::move(next), path);
    };
    for (const std::string& input : InputFilenames) {
        loadAndLink(input);
    }
    if (!definesRuntime(*module) && PipelineOverride.empty()) {
        fail("inputs do not define the Capsule runtime; compile src/runtime/guest/bpf_capsule.c with "
             "bpf-capsule-cc (matching --kernel) and link its bitcode like any other input");
    }

    Triple triple(BigEndian ? "bpfeb" : "bpfel");
    module->setTargetTriple(triple);

    // --------------------------------------------------------------- pipeline
    std::string error;
    const Target* target = TargetRegistry::lookupTarget(triple, error);
    if (!target) {
        fail(error);
    }
    TargetOptions options;
    std::unique_ptr<TargetMachine> machine(target->createTargetMachine(triple, cpu, "", options, Reloc::Static, std::nullopt, CodeGenOptLevel::Aggressive));
    if (!machine) {
        fail("cannot create BPF target machine");
    }
    module->setDataLayout(machine->createDataLayout());

    // BPF has no vector registers; LLVM 23's BPF backend crashes on a vector
    // setcc from the SLP vectorizer, so never produce one. Loop unrolling is
    // off so stackify sees loops as loops.
    PipelineTuningOptions tuning;
    tuning.LoopUnrolling = false;
    tuning.LoopVectorization = false;
    tuning.SLPVectorization = false;
    PassBuilder builder(machine.get(), tuning);
    LoopAnalysisManager loopAnalyses;
    FunctionAnalysisManager functionAnalyses;
    CGSCCAnalysisManager callGraphAnalyses;
    ModuleAnalysisManager moduleAnalyses;
    builder.registerModuleAnalyses(moduleAnalyses);
    builder.registerCGSCCAnalyses(callGraphAnalyses);
    builder.registerFunctionAnalyses(functionAnalyses);
    builder.registerLoopAnalyses(loopAnalyses);
    builder.crossRegisterProxies(loopAnalyses, functionAnalyses, callGraphAnalyses, moduleAnalyses);
    RegisterCapsulePipelineCallbacks(builder);

    std::error_code errorCode;
    auto saveModule = [&](const Twine& suffix) {
        raw_fd_ostream out(OutputFilename + suffix.str(), errorCode, sys::fs::OF_None);
        if (!errorCode) {
            WriteBitcodeToFile(*module, out);
        }
    };
    if (SaveTemps) {
        saveModule(".linked.bc");
    }

    ModulePassManager pipeline;
    std::string pipelineText = PipelineOverride.empty() ? capsulePipeline(version) : std::string(PipelineOverride);
    if (Error parseError = builder.parsePassPipeline(pipeline, pipelineText)) {
        fail("cannot construct the capsule pipeline: " + toString(std::move(parseError)));
    }
    pipeline.run(*module, moduleAnalyses);
    if (SaveTemps) {
        saveModule(".capsule.bc");
    }

    if (EmitLlvm) {
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_None);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        WriteBitcodeToFile(*module, out);
        return 0;
    }

    if (EmitAssembly) {
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_Text);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        legacy::PassManager codegen;
        if (machine->addPassesToEmitFile(codegen, out, nullptr, CodeGenFileType::AssemblyFile)) {
            fail("the BPF target cannot emit assembly files");
        }
        codegen.run(*module);
        return 0;
    }

    // ---------------------------------------------------------------- codegen
    SmallString<0> objectBuffer;
    {
        raw_svector_ostream objectStream(objectBuffer);
        legacy::PassManager codegen;
        // Post-RA spill relocation, machine flattening and final-layout repair
        // insert themselves through RegisterTargetPassConfigCallback, gated
        // on -bpf-unified-spill-pipeline injected above.
        if (machine->addPassesToEmitFile(codegen, objectStream, nullptr, CodeGenFileType::ObjectFile)) {
            fail("the BPF target cannot emit object files");
        }
        codegen.run(*module);
    }

    // LLVM emits an unusable .eh_frame even though every generated function
    // is nounwind; libbpf ignores it but warns on every open. Strip it.
    {
        auto binary = object::createBinary(MemoryBufferRef(StringRef(objectBuffer.data(), objectBuffer.size()), "capsule"));
        if (!binary) {
            fail("cannot reopen the emitted object: " + toString(binary.takeError()));
        }
        objcopy::ConfigManager config;
        config.Common.OutputFilename = OutputFilename;
        Expected<objcopy::NameOrPattern> pattern =
            objcopy::NameOrPattern::create(".eh_frame", objcopy::MatchStyle::Literal, [](Error e) -> Error { return e; });
        if (!pattern) {
            fail("objcopy pattern: " + toString(pattern.takeError()));
        }
        if (Error addError = config.Common.ToRemove.addMatcher(std::move(*pattern))) {
            fail("objcopy matcher: " + toString(std::move(addError)));
        }
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_None);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        if (Error copyError = objcopy::executeObjcopyOnBinary(config, **binary, out)) {
            fail("cannot strip .eh_frame: " + toString(std::move(copyError)));
        }
    }
    return 0;
}
