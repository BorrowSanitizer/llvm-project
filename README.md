# <a href="https://borrowsanitizer.com"><img height="60px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href="https://github.com/verus-lang/verus"><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

This is our fork of Rust's modified LLVM toolchain. It defines [a new intrinsic](https://github.com/BorrowSanitizer/llvm-project/blob/78ccf4fa642800a65f36e166502c46b91e3e3752/llvm/include/llvm/IR/Intrinsics.td#L1883C1-L1883C90) for Rust's retag instruction:
```
@llvm.retag(ptr, i64, i8, i8)
```
The first parameter is the pointer being retagged. The second is an integer offset from the pointer, indicating the range associated with the new permission created by the retag. The third and fourth parameters define the type of permission (`Frozen`, `Reserved`, `Unique`, etc.). 

We use an LLVM pass to replace these intrinsics with calls into our runtime library. The pass is implemented as an out-of-tree LLVM plugin in our [main repository](https://github.com/BorrowSanitizer/bsan).
