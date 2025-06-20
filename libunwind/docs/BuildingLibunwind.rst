.. _BuildingLibunwind:

==================
Building libunwind
==================

.. contents::
  :local:

.. _build instructions:

Getting Started
===============

On Mac OS, the easiest way to get this library is to link with -lSystem.
However if you want to build tip-of-trunk from here (getting the bleeding
edge), read on.

The basic steps needed to build libunwind are:

#. Checkout LLVM, libunwind, and related projects:

   * ``cd where-you-want-llvm-to-live``
   * ``git clone https://github.com/llvm/llvm-project.git``

#. Configure and build libunwind:

   CMake is the only supported configuration system.

   Clang is the preferred compiler when building and using libunwind.

   * ``cd where you want to build llvm``
   * ``mkdir build``
   * ``cd build``
   * ``cmake -G <generator> -DLLVM_ENABLE_RUNTIMES=libunwind [options] <llvm-monorepo>/runtimes``

   For more information about configuring libunwind see :ref:`CMake Options`.

   * ``make unwind`` --- will build libunwind.
   * ``make check-unwind`` --- will run the test suite.

   Shared and static libraries for libunwind should now be present in llvm/build/lib.

#. **Optional**: Install libunwind

   If your system already provides an unwinder, it is important to be careful
   not to replace it. Remember Use the CMake option ``CMAKE_INSTALL_PREFIX`` to
   select a safe place to install libunwind.

   * ``make install-unwind`` --- Will install the libraries and the headers


.. _CMake Options:

CMake Options
=============

Here are some of the CMake variables that are used often, along with a
brief explanation and LLVM-specific notes. For full documentation, check the
CMake docs or execute ``cmake --help-variable VARIABLE_NAME``.

**CMAKE_BUILD_TYPE**:STRING
  Sets the build type for ``make`` based generators. Possible values are
  Release, Debug, RelWithDebInfo and MinSizeRel. On systems like Visual Studio
  the user sets the build type with the IDE settings.

**CMAKE_INSTALL_PREFIX**:PATH
  Path where LLVM will be installed if "make install" is invoked or the
  "INSTALL" target is built.

**CMAKE_CXX_COMPILER**:STRING
  The C++ compiler to use when building and testing libunwind.


.. _libunwind-specific options:

libunwind specific options
--------------------------

.. option:: LIBUNWIND_ENABLE_ASSERTIONS:BOOL

  **Default**: ``ON``

  Toggle assertions independent of the build mode.

.. option:: LIBUNWIND_ENABLE_PEDANTIC:BOOL

  **Default**: ``ON``

  Compile with -Wpedantic.

.. option:: LIBUNWIND_ENABLE_WERROR:BOOL

  **Default**: ``ON``

  Compile with -Werror

.. option:: LIBUNWIND_ENABLE_SHARED:BOOL

  **Default**: ``ON``

  Build libunwind as a shared library.

.. option:: LIBUNWIND_ENABLE_STATIC:BOOL

  **Default**: ``ON``

  Build libunwind as a static archive.

.. option:: LIBUNWIND_ENABLE_CROSS_UNWINDING:BOOL

  **Default**: ``OFF``

  Enable cross-platform unwinding support.

.. option:: LIBUNWIND_ENABLE_ARM_WMMX:BOOL

  **Default**: ``OFF``

  Enable unwinding support for ARM WMMX registers.

.. option:: LIBUNWIND_ENABLE_THREADS:BOOL

  **Default**: ``ON``

  Build libunwind with threading support.

.. option:: LIBUNWIND_INSTALL_LIBRARY_DIR:PATH

  **Default**: ``lib${LIBUNWIND_LIBDIR_SUFFIX}``

  Path where built libunwind libraries should be installed. If a relative path,
  relative to ``CMAKE_INSTALL_PREFIX``.

.. option:: LIBUNWIND_ENABLE_RUST_SGX:BOOL

  **Default**: ``OFF``

