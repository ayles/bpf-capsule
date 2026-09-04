// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-capsule-ld: the BPF Capsule linker, and the core of the toolchain.
//
//   bpf-capsule-ld -mcpu=v4 --memory=arena -o program.o guest.bc [more.bc ...]
//
// Takes LLVM bitcode/IR produced by bpf-capsule-cc, rustc, or a compatible
// frontend, links it into one module together with the Capsule
// runtime, runs the whole-program capsule pipeline, and emits a
// libbpf-loadable BPF ELF. Internally this subsumes llvm-link, opt, llc and
// llvm-objcopy from the reference pipeline; the passes are linked statically,
// so there is no plugin, no tool-version matching, and no PIC relocation trap.
//
// The runtime rule: the Capsule runtime is ordinary LLVM bitcode. The CMake
// integration supplies its target-specific variant automatically; a direct
// caller must link the matching runtime input explicitly. The linker verifies
// that the runtime and platform choices agree with its target options.
#include "common.h"
#include "registry.h"
#include "softfloat.h"

#include "runtime_symbols.h"

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/StringSet.h>
#include <llvm/CodeGen/MIRParser/MIRParser.h>
#include <llvm/CodeGen/MIRPrinter.h>
#include <llvm/CodeGen/MachineFunctionPass.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/CodeGen/Passes.h>
#include <llvm/CodeGen/TargetPassConfig.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DiagnosticInfo.h>
#include <llvm/IR/DiagnosticPrinter.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManagers.h>
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
#include <llvm/Pass.h>
#include <llvm/PassRegistry.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetLoweringObjectFile.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Analysis/TargetLibraryInfo.h>

#include <string>
#include <vector>

using namespace llvm;

namespace {

cl::OptionCategory LinkerCategory("bpf-capsule-ld options");

cl::list<std::string> InputFilenames(cl::Positional, cl::desc("<input .bc/.ll/.mir files>"), cl::OneOrMore, cl::cat(LinkerCategory));
cl::opt<std::string> OutputFilename("o", cl::desc("Output BPF object"), cl::value_desc("file"), cl::Required, cl::cat(LinkerCategory));
// FiberStack registers and validates the public option. Its value is read by
// the pre-scan below because it determines flags injected into LLVM's parse.
cl::opt<unsigned> FiberStack(
    "fiber-stack", cl::desc("Bytes in each Capsule fiber stack (power of two, default 262144)"), cl::init(262144), cl::cat(LinkerCategory));
cl::opt<bool> EmitLlvm("emit-llvm", cl::desc("Stop after the capsule pipeline and emit bitcode (debugging)"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> EmitAssembly("emit-asm", cl::desc("Stop after code generation and emit BPF assembly (debugging)"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> SaveTemps("save-temps", cl::desc("Keep <output>.linked.bc and <output>.capsule.bc beside the output"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<std::string> PipelineOverride(
    "passes", cl::desc("Replace the capsule pipeline with this opt-style pass string (experiments)"), cl::init(""), cl::cat(LinkerCategory));
cl::opt<std::string> CPU("mcpu", cl::desc("BPF ISA version (v3 or v4; default v3)"), cl::init("v3"), cl::cat(LinkerCategory));
enum class MemoryMode {
    Fixed,
    Arena,
};
cl::opt<MemoryMode> Memory("memory", cl::desc("Capsule memory backend"),
    cl::values(clEnumValN(MemoryMode::Fixed, "fixed", "map-backed memory"), clEnumValN(MemoryMode::Arena, "arena", "BPF arena memory")),
    cl::init(MemoryMode::Fixed), cl::cat(LinkerCategory));
enum class AllocatorLockMode {
    Map,
    Atomic,
};
cl::opt<AllocatorLockMode> AllocatorLock("allocator-lock", cl::desc("Allocator locking implementation"),
    cl::values(clEnumValN(AllocatorLockMode::Map, "map", "portable map lease"), clEnumValN(AllocatorLockMode::Atomic, "atomic", "native BPF compare-exchange")),
    cl::init(AllocatorLockMode::Map), cl::cat(LinkerCategory));
cl::opt<bool> NativeArenaSignedLoads(
    "native-arena-signed-loads", cl::desc("Target JIT accepts sign-extending arena loads"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> IndirectJumps("indirect-jumps", cl::desc("Target supports instruction-array dispatch through gotox"), cl::init(false), cl::cat(LinkerCategory));
cl::opt<bool> NativeShift63("native-shift63", cl::desc("Target JIT accepts native 64-bit shifts by 63"), cl::init(false), cl::cat(LinkerCategory));
cl::list<std::string> RunPasses(
    "run-pass", cl::desc("Run only these machine passes on one MIR input"), cl::value_desc("pass-name"), cl::CommaSeparated, cl::cat(LinkerCategory));

[[noreturn]] void fail(const Twine& message) {
    WithColor::error(errs(), "bpf-capsule-ld") << message << "\n";
    exit(1);
}

// The whole-program Capsule pipeline. Preparation is retried only if O2
// introduces a reference that extracts another archive member; the final
// half runs once. Together their order is the compiler pipeline ABI: domains
// are computed twice, the suspend-barrier fence spans exactly O2, and the
// second i128 pass catches operations O2 introduces. Target capabilities
// appear as composition; this linker deliberately knows no Linux-version or
// JIT-architecture policy.
std::string capsulePreparationPipeline() {
    bool v4 = CPU == "v4";
    std::string pipeline = "bpf-expand-sret,"
                           "bpf-lower-capsule-call,bpf-capsule-domains,bpf-lower-capsule-exit,bpf-add-suspend-barriers,"
                           "function(bpf-validate-atomics),bpf-expand-i128,bpf-soft-float,";
    if (!v4) {
        pipeline += "bpf-lower-sdiv,";
    }
    pipeline +=
        // Even with vectorization disabled in PipelineTuningOptions, an
        // explicitly parsed default<O2> may still run target-independent
        // vector combines. BPF has no vector registers; scalarize the complete
        // post-O2 IR before any Capsule lowering or SelectionDAG sees it.
        "function(bpf-inline-policy),default<O2>,function(scalarizer<load-store>),bpf-expand-i128";
    return pipeline;
}

std::string capsuleFinalPipeline() {
    bool v4 = CPU == "v4";
    bool arena = Memory == MemoryMode::Arena;
    std::string pipeline = "function(bpf-expand-mem),bpf-internalize,globaldce,function(bpf-validate-no-float),"
                           "function(bpf-normalize-irreducible,fix-irreducible),bpf-capsule-domains,bpf-remove-suspend-barriers,";
    if (!arena) {
        pipeline += v4 ? "bpf-stackify-fixed," : "bpf-stackify-fixed-v3,";
    } else {
        pipeline += IndirectJumps ? "bpf-stackify-direct," : "bpf-stackify,";
    }
    pipeline +=
        // Stackify introduces the entry-to-driver call after whole-program O2.
        // The driver source marks only its top wrapper alwaysinline; use LLVM's
        // ordinary attribute-driven pass to fold that wrapper and GlobalDCE to
        // discard it. Stackify's conservative single-use inlining has already
        // run; this stage does not revisit application functions.
        "always-inline,globaldce,function(early-cse,gvn,adce),function(bpf-normalize-irreducible,fix-irreducible),"
        "function(bpf-define-undef),";
    if (!arena) {
        pipeline += "function(bpf-scalarize-agg),bpf-memory-fixed,";
    } else {
        pipeline += "bpf-memory-arena,";
    }
    pipeline += "function(bpf-infer-as),";
    if (arena && !NativeArenaSignedLoads) {
        pipeline += "function(bpf-lower-arena-sext),";
    }
    pipeline += "function(bpf-finalize-atomic-load-store),";
    if (!NativeShift63) {
        pipeline += "function(bpf-split-shift63),";
    }
    if (!IndirectJumps) {
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

bool hasOption(int argc, char** argv, StringRef name) {
    for (int i = 1; i < argc; ++i) {
        StringRef argument(argv[i]);
        if (argument == name || (argument.starts_with(name) && argument.drop_front(name.size()).starts_with("="))) {
            return true;
        }
    }
    return false;
}

// A native static link resolves an undefined weak symbol to zero without
// extracting an archive member for it. LLVM IR preserves the external_weak
// declaration for the object writer, but BPF has no load-time weak-symbol
// resolution. Materialize the same result before optimization so guarded
// calls and accesses fold away rather than becoming unusable BTF externs.
void resolveExternalWeak(Module& module) {
    for (GlobalValue& value : module.global_values()) {
        // Sectioned declarations are BPF loader contracts, notably optional
        // kfuncs in .ksyms. They are not ordinary ELF weak references and
        // must survive for libbpf and the kernel to resolve.
        if (value.isDeclarationForLinker() && value.hasExternalWeakLinkage() && !value.hasSection() && !value.use_empty()) {
            value.replaceAllUsesWith(Constant::getNullValue(value.getType()));
        }
    }
}

void addMachinePass(PassManagerBase& passes, StringRef name, TargetPassConfig& config) {
    if (name == "none") {
        return;
    }
    const PassInfo* info = PassRegistry::getPassRegistry()->getPassInfo(name);
    if (!info) {
        fail("run-pass " + name + " is not registered");
    }
    if (!info->getNormalCtor()) {
        fail("cannot create pass " + name);
    }
    Pass* pass = info->getNormalCtor()();
    std::string banner = "After " + std::string(pass->getPassName());
    config.addMachinePrePasses();
    passes.add(pass);
    config.addMachinePostPasses(banner);
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
    // --fiber-stack is pre-scanned because injected flag values depend on it.
    unsigned fiberStack = 262144;
    for (int i = 1; i < argc; ++i) {
        StringRef arg(argv[i]);
        if (arg.consume_front("--fiber-stack=") || arg.consume_front("-fiber-stack=")) {
            (void)arg.getAsInteger(10, fiberStack);
        } else if ((arg == "--fiber-stack" || arg == "-fiber-stack") && i + 1 < argc) {
            (void)StringRef(argv[i + 1]).getAsInteger(10, fiberStack);
        }
    }
    std::string fiberStackFlag = "-bpf-fiber-stack-size=" + std::to_string(fiberStack);
    std::string bpfStackFlag = "-bpf-stack-size=" + std::to_string(fiberStack);
    std::vector<const char*> args(argv, argv + argc);
    const bool runPassMode = hasOption(argc, argv, "-run-pass") || hasOption(argc, argv, "--run-pass");
    const bool customPipeline = hasOption(argc, argv, "-passes") || hasOption(argc, argv, "--passes");
    const bool stopCodegen = hasOption(argc, argv, "-stop-after") || hasOption(argc, argv, "--stop-after") || hasOption(argc, argv, "-stop-before") ||
        hasOption(argc, argv, "--stop-before");
    if (!customPipeline && !runPassMode) {
        args.push_back("-bpf-unified-spill-pipeline");
    }
    args.push_back(fiberStackFlag.c_str());
    args.push_back(bpfStackFlag.c_str());
    cl::ParseCommandLineOptions(args.size(), args.data(), "BPF Capsule linker\n");

    if (stopCodegen && (EmitLlvm || EmitAssembly)) {
        fail("-stop-before/-stop-after cannot be combined with --emit-llvm or --emit-asm");
    }
    if (PipelineOverride.empty()) {
        if (CPU != "v3" && CPU != "v4") {
            fail("the Capsule pipeline supports only -mcpu=v3 or -mcpu=v4");
        }
        if (Memory == MemoryMode::Fixed && NativeArenaSignedLoads) {
            fail("--native-arena-signed-loads requires --memory=arena");
        }
        if (Memory == MemoryMode::Fixed && IndirectJumps) {
            fail("--indirect-jumps requires --memory=arena");
        }
        if (Memory == MemoryMode::Arena && CPU != "v4") {
            fail("--memory=arena requires -mcpu=v4");
        }
    }

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
    Triple triple("bpfel");
    std::string targetError;
    const Target* target = TargetRegistry::lookupTarget(triple, targetError);
    if (!target) {
        fail(targetError);
    }
    const std::string cpu = CPU;
    TargetOptions options;
    std::unique_ptr<TargetMachine> machine(target->createTargetMachine(triple, cpu, "", options, Reloc::Static, std::nullopt, CodeGenOptLevel::Aggressive));
    if (!machine) {
        fail("cannot create BPF target machine");
    }

    struct ArchiveInput {
        std::string path;
        DenseSet<uint64_t> extracted;
    };

    std::unique_ptr<Module> module;
    std::vector<ArchiveInput> archives;
    auto linkModule = [&](std::unique_ptr<Module> next, const Twine& what) {
        if (!module) {
            module = std::move(next);
        } else if (Linker::linkModules(*module, std::move(next))) {
            fail("cannot link " + what);
        }
    };
    auto unresolvedSymbols = [](const Module& reference) {
        std::vector<std::string> names;
        StringSet<> seen;
        for (const GlobalValue& value : reference.global_values()) {
            // A declaration alone is not an unresolved reference. Frontends
            // commonly leave unused declarations behind, and extern weak is
            // explicitly allowed to remain absent.
            if (!value.isDeclarationForLinker() || value.use_empty() || value.hasExternalWeakLinkage() || !value.hasName()) {
                continue;
            }
            if (seen.insert(value.getName()).second) {
                names.push_back(value.getName().str());
            }
        }
        // Floating-point intrinsics become libm calls in the preparation
        // pipeline, so they are implicit archive references.
        for (std::string& name : RequiredSoftFloatLibcalls(reference)) {
            if (seen.insert(name).second) {
                names.push_back(std::move(name));
            }
        }
        // Clang represents builtin memory operations as intrinsics, but the
        // Capsule pipeline outlines non-trivial managed-memory copies to the
        // corresponding C library routine. Make that implicit dependency
        // visible to archive extraction before bpf-expand-mem runs. Unused
        // routines (for example when every copy is tiny) disappear in DCE.
        for (const Function& function : reference) {
            StringRef name;
            switch (function.getIntrinsicID()) {
                case Intrinsic::memcpy:
                    name = "memcpy";
                    break;
                case Intrinsic::memmove:
                    name = "memmove";
                    break;
                case Intrinsic::memset:
                    name = "memset";
                    break;
                default:
                    continue;
            }
            const Function* implementation = reference.getFunction(name);
            if (!function.use_empty() && (!implementation || implementation->isDeclarationForLinker()) && seen.insert(name).second) {
                names.push_back(name.str());
            }
        }
        return names;
    };
    auto extractArchive = [&](ArchiveInput& input, ArrayRef<std::string> roots) {
        auto buffer = MemoryBuffer::getFile(input.path);
        if (!buffer) {
            fail(buffer.getError().message() + ": " + input.path);
        }
        Error archiveError = Error::success();
        object::Archive archive((*buffer)->getMemBufferRef(), archiveError);
        if (archiveError) {
            fail("cannot read archive " + input.path + ": " + toString(std::move(archiveError)));
        }

        auto extract = [&](StringRef name) {
            if (GlobalValue* existing = module->getNamedValue(name); existing && !existing->isDeclarationForLinker()) {
                return false;
            }
            Expected<std::optional<object::Archive::Child>> found = archive.findSym(name);
            if (!found) {
                fail("cannot read the symbol table in " + input.path + ": " + toString(found.takeError()));
            }
            if (!*found || input.extracted.contains((*found)->getChildOffset())) {
                return false;
            }
            input.extracted.insert((*found)->getChildOffset());
            Expected<MemoryBufferRef> member = (*found)->getMemoryBufferRef();
            if (!member) {
                fail("cannot read a member of " + input.path + ": " + toString(member.takeError()));
            }
            Expected<std::unique_ptr<Module>> parsed = parseBitcodeFile(*member, context);
            if (!parsed) {
                fail("archive member in " + input.path + " is not bitcode: " + toString(parsed.takeError()));
            }
            linkModule(std::move(*parsed), input.path);
            return true;
        };

        bool changed = false;
        for (const std::string& name : roots) {
            changed |= extract(name);
        }
        // Members can introduce dependencies on later members in the same
        // archive. Resolve those to a fixed point just like a conventional
        // static linker.
        if (changed) {
            for (;;) {
                bool extractedDependency = false;
                for (const std::string& name : unresolvedSymbols(*module)) {
                    extractedDependency |= extract(name);
                }
                if (!extractedDependency) {
                    break;
                }
            }
        }
        return changed;
    };
    auto loadAndLink = [&](const std::string& path) {
        if (StringRef(path).ends_with(".a")) {
            archives.push_back({path, {}});
            if (module) {
                extractArchive(archives.back(), unresolvedSymbols(*module));
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
    bool hasMirInput = false;
    for (const std::string& input : InputFilenames) {
        hasMirInput |= StringRef(input).ends_with(".mir");
    }
    if (hasMirInput) {
        if (InputFilenames.size() != 1 || !StringRef(InputFilenames.front()).ends_with(".mir")) {
            fail("a MIR input cannot be linked with other inputs");
        }
        if (!runPassMode) {
            fail("a MIR input requires -run-pass");
        }
        if (!PipelineOverride.empty() || EmitLlvm || EmitAssembly || SaveTemps || stopCodegen) {
            fail("-run-pass cannot be combined with the Capsule pipeline or another output stage");
        }

        std::unique_ptr<MIRParser> mir = createMIRParserFromFile(InputFilenames.front(), diagnostic, context);
        if (mir) {
            module =
                mir->parseIRModule([&](StringRef, StringRef) { return std::optional<std::string>(machine->createDataLayout().getStringRepresentation()); });
        }
        if (!module) {
            diagnostic.print("bpf-capsule-ld", WithColor::error(errs(), "bpf-capsule-ld"));
            return 1;
        }
        module->setTargetTriple(triple);
        module->setDataLayout(machine->createDataLayout());

        std::error_code errorCode;
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_Text);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        legacy::PassManager passes;
        passes.add(new TargetLibraryInfoWrapperPass(TargetLibraryInfoImpl(triple)));
        auto* machineInfo = new MachineModuleInfoWrapperPass(machine.get());
        TargetPassConfig* config = machine->createPassConfig(passes);
        if (config->hasLimitedCodeGenPipeline()) {
            fail("-run-pass cannot be combined with " + config->getLimitedCodeGenPipelineReason());
        }
        passes.add(config);
        passes.add(machineInfo);
        config->printAndVerify("");
        for (const std::string& name : RunPasses) {
            addMachinePass(passes, name, *config);
        }
        config->setInitialized();
        passes.add(createPrintMIRPass(out));
        passes.add(createFreeMachineFunctionPass());
        machine->getObjFileLowering()->Initialize(machineInfo->getMMI().getContext(), *machine);
        if (mir->parseMachineFunctions(*module, machineInfo->getMMI())) {
            return 1;
        }
        passes.run(*module);
        return 0;
    }
    if (runPassMode) {
        fail("-run-pass is for .mir input only");
    }

    for (const std::string& input : InputFilenames) {
        loadAndLink(input);
    }
    if (!module) {
        fail("inputs contain no LLVM bitcode modules");
    }
    const bool hasRuntime = definesRuntime(*module);
    if (!hasRuntime && PipelineOverride.empty()) {
        fail("inputs do not define the Capsule runtime; use bpf_capsule_object or link matching runtime bitcode explicitly");
    }

    // Runtime and platform code are compiled as SDK-owned inputs, but their
    // target-dependent choices are made here. Refuse stale/mismatched inputs
    // instead of silently emitting code for a different memory or atomic
    // model.
    auto checkBuildMarker = [&](StringRef name, unsigned selected, const Twine& description, bool required) {
        if (GlobalVariable* marker = module->getNamedGlobal(name)) {
            auto* declared = dyn_cast_or_null<ConstantInt>(marker->getInitializer());
            if (!declared || declared->getZExtValue() != selected) {
                fail("linked Capsule " + description + " disagrees with its linker option");
            }
        } else if (required) {
            fail("linked Capsule " + description + " is not declared by its build inputs");
        }
    };
    checkBuildMarker(bpf::sym::MemoryBackend, Memory == MemoryMode::Arena ? 1 : 0, "runtime memory backend", hasRuntime);
    checkBuildMarker(bpf::sym::AllocatorLockMode, AllocatorLock == AllocatorLockMode::Atomic ? 1 : 0, "platform allocator lock", false);

    // Function target attributes control BPF instruction selection after the
    // modules have been linked. Reject a concrete frontend/linker disagreement
    // instead of silently generating a mixture of ISA versions. Frontends that
    // leave the attribute absent (and rustc-generated shims marked "generic")
    // are compatible with either supported ISA and inherit the link target.
    const bool enforceTargetCpu = PipelineOverride.empty() || CPU.getNumOccurrences() != 0;
    auto prepareLinkedModule = [&] {
        module->setTargetTriple(triple);
        module->setDataLayout(machine->createDataLayout());
        if (!enforceTargetCpu) {
            return;
        }
        for (Function& function : *module) {
            if (function.isIntrinsic()) {
                continue;
            }
            Attribute attribute = function.getFnAttribute("target-cpu");
            if (attribute.isValid() && attribute.isStringAttribute() && attribute.getValueAsString() != "generic" && attribute.getValueAsString() != CPU) {
                fail("function " + function.getName() + " was compiled for -mcpu=" + attribute.getValueAsString() + ", but the linker selected -mcpu=" + CPU);
            }
            function.addFnAttr("target-cpu", CPU);
        }
    };
    prepareLinkedModule();

    // --------------------------------------------------------------- pipeline
    auto runPipeline = [&](Module& targetModule, StringRef text) {
        // BPF has no vector registers; LLVM 23's BPF backend crashes on a
        // vector setcc from the SLP vectorizer, so never produce one. Loop
        // unrolling is off so stackify sees loops as loops.
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

        ModulePassManager pipeline;
        if (Error parseError = builder.parsePassPipeline(pipeline, text)) {
            fail("cannot construct the capsule pipeline: " + toString(std::move(parseError)));
        }
        pipeline.run(targetModule, moduleAnalyses);
    };

    auto saveModule = [&](const Twine& suffix) {
        std::string path = OutputFilename + suffix.str();
        std::error_code errorCode;
        raw_fd_ostream out(path, errorCode, sys::fs::OF_None);
        if (errorCode) {
            fail(errorCode.message() + ": " + path);
        }
        WriteBitcodeToFile(*module, out);
    };
    if (!PipelineOverride.empty()) {
        if (SaveTemps) {
            saveModule(".linked.bc");
        }
        resolveExternalWeak(*module);
        runPipeline(*module, PipelineOverride);
    } else {
        // O2 may introduce an ordinary C-library call (for example, replacing
        // a constant-format fprintf with fwrite). A native LTO link resolves
        // that call after optimization. Do the same for bitcode archives:
        // retry only the preparation half from an untouched linked module,
        // then run stackification and code generation once.
        for (;;) {
            std::unique_ptr<Module> prepared = CloneModule(*module);
            resolveExternalWeak(*prepared);
            runPipeline(*prepared, capsulePreparationPipeline());
            std::vector<std::string> introduced = unresolvedSymbols(*prepared);
            bool extracted = false;
            for (ArchiveInput& archive : archives) {
                extracted |= extractArchive(archive, introduced);
            }
            if (extracted) {
                prepareLinkedModule();
                continue;
            }
            if (SaveTemps) {
                saveModule(".linked.bc");
            }
            module = std::move(prepared);
            break;
        }
        runPipeline(*module, capsuleFinalPipeline());
    }
    if (SaveTemps) {
        saveModule(".capsule.bc");
    }

    if (EmitLlvm) {
        std::error_code errorCode;
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_None);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        WriteBitcodeToFile(*module, out);
        return 0;
    }

    if (EmitAssembly) {
        std::error_code errorCode;
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

    // LLVM's -stop-before/-stop-after contract is to serialize MIR instead of
    // producing the requested final file type. Keep that boundary visible so
    // the result can be inspected and fed back through -run-pass.
    if (stopCodegen) {
        std::error_code errorCode;
        raw_fd_ostream out(OutputFilename, errorCode, sys::fs::OF_Text);
        if (errorCode) {
            fail(errorCode.message() + ": " + OutputFilename);
        }
        legacy::PassManager codegen;
        if (machine->addPassesToEmitFile(codegen, out, nullptr, CodeGenFileType::ObjectFile)) {
            fail("the BPF target cannot emit MIR at the requested pipeline boundary");
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
        std::error_code errorCode;
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
