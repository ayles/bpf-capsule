// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
extern int symbol_that_must_not_be_linked(void);

int unused_archive_member(void) {
    return symbol_that_must_not_be_linked();
}
