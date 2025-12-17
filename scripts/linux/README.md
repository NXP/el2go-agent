# Table of Contents

1. [Introduction](#1-introduction)
2. [Toolchain](#2-toolchain)
   - 2.1. [Install in a default path](#21-install-in-a-default-path)
   - 2.2. [Install in a custom path](#22-install-in-a-custom-path)
   - 2.3. [Additional toolchain options](#23-additional-toolchain-options)
3. [External dependencies](#3-external-dependencies)
   - 3.1. [Building MbedTLS](#31-building-mbedtls)
   - 3.2. [Building SMW](#32-building-smw)
4. [Project configuration and compilation](#4-project-configuration-and-compilation)
5. [Useful scripts](#5-useful-scripts)
   - 5.1. [Configure script](#51-configure-script)
   - 5.2. [Build script](#52-build-script)
   - 5.3. [Example of configuring and building the project](#53-example-of-configuring-and-building-the-project)
## 1. Introduction

This guide outlines the steps to build the __EdgeLock 2GO Agent__, including dependencies, configuration, compilation, and installation on i.MX MPU 64-bit platforms. The EdgeLock 2GO Agent can be built for other platforms, but these scripts target only i.MX MPU, 64-bit, Linux-based platforms.

The EdgeLock 2GO Agent can be built as part of the __i.MX Linux OS BSP__ using the Yocto build system. In this setup, __Yocto__ handles the configuration, compilation, and installation processes automatically.

Alternatively, the agent can be built __outside of Yocto__ as a standalone project. In this case, all required dependencies must be manually built and configured before building the agent. This guide focuses on the standalone build approach using the provided build scripts.

## 2. Toolchain

The EdgeLock 2GO Agent can run on various ARM-based processors. However, these build scripts specifically target the 64-bit ARM architecture for i.MX platforms. As such, a 64-bit GNU ARM toolchain is required for cross-compilation. Additionally, a toolchain configuration file must be provided for use by other scripts during the compilation of sub-components, ensuring the correct toolchain settings are applied.

### 2.1. Install in a default path

To install the toolchain into the ```./toolchains``` directory within the source tree, run the following CMake script:

```bash
cmake -DFORCE_TOOLCHAIN_INSTALL=True -P ./scripts/linux/aarch64_toolchain.cmake
```

This command will download the required toolchain from the Arm developer website and place it in the ```./toolchains``` folder at the root of the project. The toolchain will then be extracted automatically.

### 2.2. Install in a custom path

To install the toolchain in a custom directory, execute the following CMake script:

```bash
cmake -DFORCE_TOOLCHAIN_INSTALL=True -DTOOLCHAIN_PATH=[install path] -P ./scripts/linux/aarch64_toolchain.cmake
```

This configuration will download the toolchain from the Arm developer website into the given path specified with the TOOLCHAIN_PATH option.

Alternatively, you can use the provided script to achieve the same result:

```bash
./scripts/linux/build.sh toolchain toolpath=[install path]
```

### 2.3. Additional toolchain options

Users can customize additional toolchain options, such as selecting a specific toolchain revision when multiple versions are available.

<table>
<caption id="table-additional-toolchain-options">Additional toolchain options</caption>
<thead>
<tr>
  <th>Option</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>TOOLCHAIN_NAME</td>
  <td>Specifies a GNU ARM toolchain name (e.g. aarch64-linux-gnu)</td>
</tr>
<tr>
  <td>TOOLCHAIN_VERSION</td>
  <td>Specifies a specific GNU ARM toolchain version (other than default one).
  This option combined with the TOOLCHAIN_NAME is used to define the toolchain
  complete name `arm-gnu-toolchain-[TOOLCHAIN_VERSION]-x86_64-[TOOLCHAIN_NAME]`</td>
</tr>
</tbody>
</table>

## 3. External dependencies

The __EdgeLock 2GO Agent__ requires several external libraries and their corresponding header files to build. These libraries provide essential functionality such as secure communication with the EdgeLock 2GO Server and interaction with security subsystems.

<table>
<caption id="table-external-dependencies">External dependencies</caption>
<thead>
<tr>
  <th>External dependency</th>
  <th>Type</th>
  <th>Comments</th>
</tr>
</thead>
<tbody>
<tr>
  <td><b>MbedTLS library</b></td>
  <td>Static library</td>
  <td>Provides cryptographic functions and TLS/SSL support for secure communication</td>
</tr>
<tr>
  <td><b><a href="https://github.com/nxp-imx/imx-smw">Security Middleware Library (SMW)</a></b></td>
  <td>Shared library</td>
  <td>The Security Middleware Library (SMW) provides a unified API to interact with the i.MX Secure Subsystems (<code>libsmw.so</code>)</td>
</tr>
</tbody>
</table>

### 3.1. Building MbedTLS

The MbedTLS library provides cryptographic primitives and TLS/SSL functionality required by the EdgeLock 2GO Agent to establish secure connections with the EdgeLock 2GO Server.

The following script can be used to build MbedTLS:

```bash
cmake -DTOOLCHAIN_PATH=[tool path] -DCMAKE_TOOLCHAIN_FILE=./scripts/linux/aarch64_toolchain.cmake -DMbedTLS_BUILD_DIR=[build path] -DMbedTLS_SRC_PATH=[source path] -DMbedTLS_ROOT=[export path] -P ./scripts/linux/build_mbedtls.cmake
```

Alternatively, you can use the provided script to achieve the same result:

```bash
./scripts/linux/build.sh mbedtls toolpath=[tool path] export=[export path] src=[source path] out=[build path]
```

The scripts download the MbedTLS sources into the specified source folder, build it, and then export the resulting binaries to the designated export folder.

**Optional parameters:**
- `branch=[branch name]` - Specify a particular MbedTLS branch to checkout
- `revision=[revision]` - Specify a particular MbedTLS revision/commit

### 3.2. Building SMW

The EdgeLock 2GO Agent uses the __Security Middleware (SMW) library__ to execute operations on the EdgeLock Secure Enclave. The SMW library has its own set of dependencies, which are not covered in this document. For detailed instructions on how to build each SMW dependency, please refer to the <a href="https://github.com/nxp-imx/imx-smw">Security Middleware Library (SMW) Documentation</a>.

Alternatively, you can use the provided script to build the SMW library and its dependencies:

```bash
./scripts/linux/build.sh smw toolpath=[tool path] out=[smw build folder path] src=[source path] platform=[imx93evk/imx91evk/imx8ulpevk] export=[smw export path]
```

The script assumes that the SMW is available in the __[source path]__ together with the needed dependencies (see <a href="https://github.com/nxp-imx/imx-smw">Security Middleware Library (SMW) Documentation</a>).

## 4. Project configuration and compilation

Before building the project it must be configured and all the dependencies resolved.

The project uses CMake as its build system, with several key configuration options:

<table>
<caption id="table-build-environment-options">Build environment options</caption>
<thead>
<tr>
  <th>Project cmake variable</th>
  <th>CMake option</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td>CMAKE_TOOLCHAIN_FILE</td>
  <td>-DCMAKE_TOOLCHAIN_FILE=[/path/to/script]</td>
  <td>Path to the script configuring the cross-compiler toolchain. The following script can be used: <code>./scripts/linux/aarch64_toolchain.cmake</code></td>
</tr>
<tr>
  <td>TOOLCHAIN_PATH</td>
  <td>-DTOOLCHAIN_PATH=[/path/to/toolchain]</td>
  <td>Configure the toolchain path if it's not the default one. Must be the path to the folder containing the toolchain folder</td>
</tr>
<tr>
  <td>CMAKE_BUILD_TYPE</td>
  <td>-DCMAKE_BUILD_TYPE=[Debug/Release]</td>
  <td>The build type of the project can be configured, with <b>Release</b> being the default option</td>
</tr>
<tr>
  <td>CMAKE_INSTALL_PREFIX</td>
  <td>-DCMAKE_INSTALL_PREFIX=[/path/to/install]</td>
  <td>Defines the installation prefix directory when executing <code>make install</code></td>
</tr>
<tr>
  <td>CMAKE_INSTALL_LIBDIR</td>
  <td>-DCMAKE_INSTALL_LIBDIR=[lib directory]</td>
  <td>Defines the library installation directory. Default is <code>lib</code></td>
</tr>
<tr>
  <td>NXP_SMW_DIR</td>
  <td>-DNXP_SMW_DIR=[/path/to/config]</td>
  <td>Path to the folder where configuration packages for the SMW library are located</td>
</tr>
<tr>
  <td>MbedTLS_DIR</td>
  <td>-DMbedTLS_DIR=[/path/to/config]</td>
  <td>Path to the folder where configuration packages for the MbedTLS library are located</td>
</tr>
</tbody>
</table>

## 5. Useful scripts

Two scripts are available to simplify the build process: one for building dependencies and configuring the project, and another for building specific components.

### 5.1. Configure script

```bash
./scripts/linux/configure.sh
```

This shell script builds the project dependencies and configures the EdgeLock 2GO Agent. It assumes that the sources for external dependencies are already available (see [Dependencies table](#table-dependencies) below). Other external dependencies are downloaded by the build scripts.

**Usage:**

```bash
./scripts/linux/configure.sh [build directory] [platform] toolpath=[path/to/toolpath]
```

**Parameters:**

- `[build directory]` - The directory where the build artifacts will be placed
- `[platform]` - Target i.MX platform: `imx91evk`, `imx8ulpevk`, or `imx93evk`
- `toolpath=[path/to/toolpath]` - (Optional) Path to the toolchain. If not specified, the script will use the default toolchain location at `/toolchains`

**Description:**

The configure script performs the following operations:
1. Validates the target platform
2. Installs the toolchain (if needed)
3. Downloads and builds MbedTLS
4. Builds the SMW library and its dependencies
5. Configures the EdgeLock 2GO Agent project using CMake

**Expected folder structure:**

The script expects the following directory structure:

```
parent-folder/
├── smw/                    (EdgeLock 2GO Agent dependency)
├── optee-client/           (SMW dependency)
├── optee-os/               (SMW dependency)
├── secure_enclave/         (SMW dependency)
├── mbedtls/                (Optional - downloaded if not present)
└── simw-devicelink/        (Run script from here)
```

<table>
<caption id="table-dependencies">Dependencies</caption>
<thead>
<tr>
  <th>Source</th>
  <th>Default Path</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
<tr>
  <td><a href="https://github.com/nxp-imx/imx-smw">Security Middleware Library (SMW)</a></td>
  <td>../smw</td>
  <td>SMW library source. To build SMW, its dependencies must also be available. For more details see <a href="https://github.com/nxp-imx/imx-smw">Security Middleware Library (SMW) Documentation</a></td>
</tr>
<tr>
  <td><a href="https://github.com/Mbed-TLS/mbedtls">MbedTLS</a></td>
  <td>../mbedtls</td>
  <td>MbedTLS library source. If not present, it will be downloaded automatically</td>
</tr>
</tbody>
</table>


### 5.2. Build script

```bash
./scripts/linux/build.sh
```

This script provides a unified interface for building the EdgeLock 2GO Agent and its dependencies. It can be used for multiple purposes including building MbedTLS, SMW, and the agent itself.

**Usage:**

```bash
./scripts/linux/build.sh [command] [options]
```

**Available Commands:**

- `toolchain` - Download and install the ARM toolchain
- `mbedtls` - Build the MbedTLS library
- `smw` - Build the Security Middleware library
- `configure` - Configure the EdgeLock 2GO Agent project
- `build` - Build the EdgeLock 2GO Agent
- `install` - Install the built agent
- `package` - Create a tarball package of the agent


### 5.3. Example of configuring and building the project

This example demonstrates the complete workflow for configuring, building, and installing the EdgeLock 2GO Agent.

**Prerequisites:**

Ensure the required dependency sources are available:
- SMW source at `../smw`
- SMW dependencies (optee-client, optee-os, secure_enclave) as siblings to the SMW directory

**Step 1: Configure the project**

```bash
./scripts/linux/configure.sh [build directory] [architecture] toolpath=[path/to/toolpath]
```

This command will:
- Create the build directory at `[build directory]`
- Configure for the `[architecture]` platform
- Use the toolchain located at `[path/to/toolpath]`
- Build all required dependencies (MbedTLS, SMW)
- Configure the CMake project

**Step 2: Build the project**

```bash
./scripts/linux/build.sh build out=[build directory]
```

This will compile the EdgeLock 2GO Agent libraries and binaries.

**Step 3: Install the project**

```bash
./scripts/linux/build.sh install out=[build directory] dest=[install_directory]
```

This will install the built artifacts to `[install_directory]`.

**Alternative: Create a package**

Instead of installing directly, you can create a tarball package:

```bash
./scripts/linux/build.sh package out=[build directory]
```

This creates `el2go_agent.tar.gz` in the `[build directory]` containing all installation files.

>  **Note:**
> To avoid relative path issues, it is advisable to use absolute paths for all directory arguments.