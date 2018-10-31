echo on
set PLATFORM=x86
if "%PLATFORM%" == "x86" set RUST_INSTALL=i686-pc-windows-msvc
if "%PLATFORM%" == "x64" set RUST_INSTALL=x86_64-pc-windows-msvc
appveyor AddMessage "Platform rust: %RUST_INSTALL%"
appveyor DownloadFile "https://static.rust-lang.org/dist/rust-nightly-%RUST_INSTALL%.exe" -FileName rust-install.exe
"./rust-install.exe" /VERYSILENT /NORESTART /DIR="C:\Rust\"
SET PATH=%PATH%;C:\Rust\bin
rustc -V
cargo -V

vcpkg integrate install
vcpkg install openssl:x64-windows
vcpkg install openssl:x86-windows
set VCPKGRS_DYNAMIC=1

appveyor DownloadFile https://www.libsdl.org/release/SDL2-devel-2.0.4-VC.zip -FileName sdl2-dev.zip
mkdir C:\sdl2
7z x sdl2-dev.zip -oC:\sdl2\ -y
cp C:\sdl2\SDL2-2.0.4\lib\%PLATFORM%\SDL2.lib C:\Rust\lib\rustlib\%RUST_INSTALL%\lib\SDL2.lib

cargo build
