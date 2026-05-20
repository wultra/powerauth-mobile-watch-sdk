#!/bin/bash
# ----------------------------------------------------------------------------
set -e
set +v
###############################################################################
# PowerAuth2ForWatch build
#
# The main purpose of this script is build and prepare files hierarchy for 
# cocoapod library distribution. The result of the build process is a xcframework 
# with all supported platforms and architectures.
#
# Script is using following folders (if not changed):
#
#    ./Lib/FW.xcframework - final xcframework with dynamic library
#    ./Tmp                - for all temporary data
#
# ----------------------------------------------------------------------------

###############################################################################
# Include common functions...
# -----------------------------------------------------------------------------
TOP=$(dirname $0)
source "${TOP}/common-functions.sh"
source "${TOP}/config-apple.sh"
source "${TOP}/config-apple-ext.sh"
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"

#
# Source headers & Xcode project location
#
XCODE_DIR="${SRC_ROOT}"

#
# Platforms & CPU architectures
#

# WatchOS
WOS_FRAMEWORK="PowerAuth2ForWatch"
WOS_PLATFORMS="watchOS watchOS_Simulator"
WOS_PROJECT="${XCODE_DIR}/PowerAuth2ForWatch.xcodeproj"

# Variables loaded from command line
PLATFORMS=''
VERBOSE=1
FULL_REBUILD=1
CLEANUP_AFTER=1
OUT_DIR=''
OUT_FW=''
TMP_DIR=''
OPT_LEGACY_ARCH=0
OPT_USE_BITCODE=0
OPT_WEAK_TVOS=0

DO_WATCHOS=1

# -----------------------------------------------------------------------------
# USAGE prints help and exits the script with error code from provided parameter
# Parameters:
#   $1   - error code to be used as return code from the script
# -----------------------------------------------------------------------------
function USAGE
{
    echo ""
    echo "Usage:  $CMD  [options]"
    echo ""
    echo "options are:"
    echo ""
    echo "  -nc | --no-clean  disable 'clean' before 'build'"
    echo "                    also disables temporary data cleanup after build"
    echo "  -v0               turn off all prints to stdout"
    echo "  -v1               print only basic log about build progress"
    echo "  -v2               print full build log with rich debug info"
    echo "  --out-dir path    changes directory for final framework"
    echo "                    and source codes will be copied"
    echo "  --tmp-dir path    changes temporary directory to |path|"
    echo "  -h | --help       prints this help information"
    echo ""
    echo "legacy options:"
    echo ""
    echo "  --legacy-archs    compile also legacy architectures"
    echo "  --use-bitcode     compile with enabled bitcode"
    echo ""
    exit $1
}

# -----------------------------------------------------------------------------
# GET_PLATFORM_ARCH
#   Print a list of architectures for given build platform. For example,
#   for 'iOS' function prints 'armv7 armv7s arm64 arm64e'.
#
# GET_PLATFORM_SDK
#   Print a list of architectures for given build platform. For example,
#    for 'iOS' function prints 'iphoneos'.
#
# GET_PLATFORM_DESTINATION
#   Print a value for -destination parameter used to set proper build
#   target for xcodebuild. For example, for 'iOS' function prints
#   'generic/platform=iOS'.
#
# GET_PLATFORM_TARGET
#   Print a build target for given build platform. For example, for 'watchOS'
#   function prints 'PowerAuth2ForWatch'.
#
# GET_PLATFORM_PROJECT
#   Print a path to xcode project for given build platform. For example, for 'iOS'
#   function prints '.../PowerAuth2ForWatch.xcodeproj'.
#
# GET_PLATFORM_MIN_OS_VER
#   Print a minimum supported OS version for given build platform. For example, 
#   for 'iOS' function prints '${MIN_VER_IOS}'.
#
# GET_PLATFORM_SCHEME
#   Print build scheme for given build platform. For example, for 'iOS'
#   function prints 'PowerAuth2ForWatch'
#
# Parameters:
#   $1   - build platform (e.g. 'iOS', 'tvOS', etc...)
# -----------------------------------------------------------------------------
function GET_PLATFORM_ARCH
{
    case $1 in
        watchOS)            echo ${ARCH_WATCHOS} ;;
        watchOS_Simulator)  echo ${ARCH_WATCHOS_SIM} ;;
        *) FAILURE "Cannot determine architecture. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SDK
{
    case $1 in
        watchOS)            echo 'watchos' ;;
        watchOS_Simulator)  echo 'watchsimulator' ;;
        *) FAILURE "Cannot determine platform SDK. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_DESTINATION
{
    case $1 in
        watchOS)            echo 'generic/platform=watchOS' ;;
        watchOS_Simulator)  echo 'generic/platform=watchOS Simulator' ;;
        *) FAILURE "Cannot determine platform destination. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_TARGET
{
    case $1 in
        watchOS | watchOS_Simulator)            echo 'PowerAuth2ForWatch' ;;
        *) FAILURE "Cannot determine platform target. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_PROJECT
{
    case $1 in
        watchOS | watchOS_Simulator)            echo "${XCODE_DIR}/PowerAuth2ForWatch.xcodeproj" ;;
        *) FAILURE "Cannot determine platform project. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_MIN_OS_VER
{
    case $1 in
        watchOS | watchOS_Simulator)    echo ${MIN_VER_WATCHOS} ;;
        *) FAILURE "Cannot determine minimum supported OS version. Unsupported platform: '$1'" ;;
    esac
}
function GET_PLATFORM_SCHEME
{
    case $1 in
        watchOS | watchOS_Simulator)            echo 'PowerAuth2ForWatch' ;;
        *) FAILURE "Cannot determine build scheme. Unsupported platform: '$1'" ;;
    esac
}
function GET_DEPLOYMENT_TARGETS
{
    local target=
    target+=" IPHONEOS_DEPLOYMENT_TARGET=${MIN_VER_IOS}"
    target+=" TVOS_DEPLOYMENT_TARGET=${MIN_VER_TVOS}"
    target+=" MACOSX_DEPLOYMENT_TARGET=${MIN_VER_CATALYST}"
    target+=" WATCHOS_DEPLOYMENT_TARGET=${MIN_VER_WATCHOS}"
    echo $target
}
function GET_BITCODE_OPTION
{
    [[ x$OPT_USE_BITCODE == x0 ]] && echo "ENABLE_BITCODE=NO"
    [[ x$OPT_USE_BITCODE == x1 ]] && echo "ENABLE_BITCODE=YES"
}

# -----------------------------------------------------------------------------
# Performs xcodebuild command for a single platform (iphone / simulator)
# Parameters:
#   $1   - platform (iOS, iOS_Simulator, etc...)
#   $2   - architecture (arm64, arm64_32, etc...)
#   $3   - set to 1, to clean the build folder
# -----------------------------------------------------------------------------
function BUILD_COMMAND
{
    local PLATFORM="$1"
    local ARCHITECTURE="$2"
    local DO_CLEAN="$3"
    
    local PLATFORM_DIR=$"${TMP_DIR}/${PLATFORM}_${ARCHITECTURE}"
    local ARCHIVE_PATH="${PLATFORM_DIR}/${OUT_FW}.xcarchive"
    
    local PLATFORM_ARCHS="$ARCHITECTURE"
    local PLATFORM_SDK="$(GET_PLATFORM_SDK $PLATFORM)"
    local PLATFORM_TARGET="$(GET_PLATFORM_TARGET $PLATFORM)"
    local PLATFORM_DEST="$(GET_PLATFORM_DESTINATION $PLATFORM)"
    local MIN_SDK_VER="$(GET_PLATFORM_MIN_OS_VER $PLATFORM)"
    local PROJECT="$(GET_PLATFORM_PROJECT $PLATFORM)"
    local SCHEME=$(GET_PLATFORM_SCHEME $PLATFORM)
    local DEPLOYMENT_TARGETS=$(GET_DEPLOYMENT_TARGETS)
    local BITCODE_OPTION=$(GET_BITCODE_OPTION)
    
    LOG_LINE
    LOG "Building ${PLATFORM} (${MIN_SDK_VER}+) for architecture ${PLATFORM_ARCHS}"
    
    DEBUG_LOG "Executing 'archive' for target ${PLATFORM_TARGET} ${PLATFORM_TARGET} :: ${PLATFORM_ARCHS}"
    
    local COMMAND_LINE="xcodebuild archive -project \"${PROJECT}\" -scheme ${SCHEME}"
    COMMAND_LINE+=" -archivePath \"${ARCHIVE_PATH}\""
    COMMAND_LINE+=" -sdk ${PLATFORM_SDK} ARCHS=\"${PLATFORM_ARCHS}\""
    COMMAND_LINE+=" -destination \"${PLATFORM_DEST}\""
    COMMAND_LINE+=" SKIP_INSTALL=NO BUILD_LIBRARIES_FOR_DISTRIBUTION=YES"
    COMMAND_LINE+=" ${DEPLOYMENT_TARGETS} ${BITCODE_OPTION}"
    [[ $VERBOSE -lt 2 ]] && COMMAND_LINE+=" -quiet"
    
    DEBUG_LOG ${COMMAND_LINE}
    eval ${COMMAND_LINE}

    # Add produced platform framework to the list
    local FINAL_FW="${ARCHIVE_PATH}/Products/Library/Frameworks/${OUT_FW}.framework"
    [[ ! -d "${FINAL_FW}" ]] && FAILURE "Xcode build did not produce '${OUT_FW}.framework' for platform ${PLATFORM}"
    ALL_FAT_LIBS+=("${FINAL_FW}")
}


# -----------------------------------------------------------------------------
# Merge multiple single-arch frameworks for the same platform into one fat
# framework using lipo. Required because xcodebuild -create-xcframework
# rejects more than one framework per platform+environment combination.
# Parameters:
#   $1   - output directory for the merged framework
#   $2+  - paths to the per-arch frameworks to merge
# Prints the path of the merged (or single) framework to stdout.
# -----------------------------------------------------------------------------
function MERGE_PLATFORM_LIBS
{
    local MERGED_DIR="$1"
    shift
    local FRAMEWORKS=("$@")

    if [[ ${#FRAMEWORKS[@]} -eq 1 ]]; then
        echo "${FRAMEWORKS[0]}"
        return 0
    fi

    local BASE_FW="${FRAMEWORKS[0]}"
    local FW_NAME=$(basename "${BASE_FW}")
    local BINARY_NAME="${FW_NAME%.framework}"
    local MERGED_FW="${MERGED_DIR}/${FW_NAME}"

    $MD "${MERGED_DIR}"
    $CP -R "${BASE_FW}" "${MERGED_DIR}/"

    local LIPO_INPUTS=()
    for FW in "${FRAMEWORKS[@]}"; do
        LIPO_INPUTS+=("${FW}/${BINARY_NAME}")
    done

    DEBUG_LOG "Merging ${#FRAMEWORKS[@]} slices into fat framework: ${MERGED_FW}"
    lipo -create "${LIPO_INPUTS[@]}" -output "${MERGED_FW}/${BINARY_NAME}"

    echo "${MERGED_FW}"
}

# -----------------------------------------------------------------------------
# Build xcframework
# -----------------------------------------------------------------------------
function BUILD_LIBRARY
{
    LOG_LINE
    LOG "Building $OUT_FW for supported platforms..."
    LOG "  - macOS $(sw_vers -productVersion) ($(uname -m))"
    LOG "  - Xcode $(GET_XCODE_VERSION --full)"
    LOG_LINE

    BUILD_PATCH_ARCHITECTURES

    [[ x$FULL_REBUILD == x1 ]] && CLEAN_COMMAND

    local XCFW_PATH="${OUT_DIR}/${OUT_FW}.xcframework"
    local XCFW_ARGS=

    for PLATFORM in ${PLATFORMS}
    do
        ALL_FAT_LIBS=()
        for ARCH in $(GET_PLATFORM_ARCH $PLATFORM)
        do
            BUILD_COMMAND $PLATFORM $ARCH $FULL_REBUILD
        done

        local MERGED_FW
        MERGED_FW=$(MERGE_PLATFORM_LIBS "${TMP_DIR}/${PLATFORM}_fat" "${ALL_FAT_LIBS[@]}")
        XCFW_ARGS+="-framework ${MERGED_FW} "
        DEBUG_LOG "  - source fw: ${MERGED_FW}"
    done

    LOG_LINE
    LOG "Creating final ${OUT_FW}.xcframework..."
    DEBUG_LOG "  - target fw: ${XCFW_PATH}"
    $MD "${OUT_DIR}"
    xcodebuild -create-xcframework $XCFW_ARGS -output "${XCFW_PATH}"
}

# -----------------------------------------------------------------------------
# Clear project for specific scheme
# Parameters:
#   $1  -   configuration name
# -----------------------------------------------------------------------------
function CLEAN_COMMAND
{
    LOG_LINE
    LOG "Cleaning build folder..."
    
    local QUIET=
    if [ $VERBOSE -lt 2 ]; then
        QUIET=" -quiet"
    fi
    local ALL_PLATFORMS=( $PLATFORMS )
    local SCHEME=$(GET_PLATFORM_SCHEME ${ALL_PLATFORMS[0]})
    local PROJECT=$(GET_PLATFORM_PROJECT ${ALL_PLATFORMS[0]})
    local DESTINATION="$(GET_PLATFORM_DESTINATION ${ALL_PLATFORMS[0]})"
    local COMMAND_LINE="xcodebuild clean -project \"${PROJECT}\" -scheme ${SCHEME} ${QUIET} -destination ${DESTINATION}"
    
    DEBUG_LOG $COMMAND_LINE
    eval $COMMAND_LINE
}

function DO_BUILD_WATCHOS
{
    OUT_FW=${WOS_FRAMEWORK}
    PLATFORMS="${WOS_PLATFORMS}"
    BUILD_LIBRARY
}

###############################################################################
# Script's main execution starts here...
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        watchos)
            DO_WATCHOS=1
            ;;
        -nc | --no-clean)
            FULL_REBUILD=0 
            CLEANUP_AFTER=0
            ;;
        --legacy-archs)
            OPT_LEGACY_ARCH=1
            ;;
        --use-bitcode)
            OPT_USE_BITCODE=1
            ;;
        --tmp-dir)
            TMP_DIR="$2"
            shift
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift
            ;;
        -v*)
            SET_VERBOSE_LEVEL_FROM_SWITCH $opt
            ;;
        -h | --help)
            USAGE 0
            ;;
        *)
            USAGE 1
            ;;
    esac
    shift
done

# Defaulting out & temporary folders
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="${TOP}/Lib/${PLATFORM_SDK}"
fi
if [ -z "$TMP_DIR" ]; then
    TMP_DIR="${TOP}/Tmp"
fi

REQUIRE_COMMAND xcodebuild
REQUIRE_COMMAND lipo
REQUIRE_COMMAND otool

# -----------------------------------------------------------------------------
# Real job starts here :) 
# -----------------------------------------------------------------------------

#
# Prepare target directories
#
[[ x$FULL_REBUILD == x1 ]] && [[ -d "${OUT_DIR}" ]] && $RM -r "${OUT_DIR}"
[[ x$FULL_REBUILD == x1 ]] && [[ -d "${TMP_DIR}" ]] && $RM -r "${TMP_DIR}"
$MD "${OUT_DIR}"
$MD "${TMP_DIR}"

#
# Build
#
[[ x$DO_WATCHOS == x1    ]] && DO_BUILD_WATCHOS

#
# Remove temporary data
#
if [ x$CLEANUP_AFTER == x1 ]; then
    LOG_LINE
    LOG "Removing temporary data..."
    $RM -r "${TMP_DIR}"
fi

EXIT_SUCCESS
