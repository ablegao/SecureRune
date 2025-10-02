cmake_minimum_required(VERSION 3.16)

project(
  SecureRune
  VERSION 0.1
  LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_PREFIX_PATH "/Users/ablegao/Qt/6.9.3/macos/lib/cmake/Qt6")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(PkgConfig REQUIRED)
find_package(QT NAMES Qt6 REQUIRED COMPONENTS Widgets LinguistTools)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets LinguistTools)
find_package(OpenSSL REQUIRED)

set(TS_FILES SecureRune_en_VI.ts)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    encodedecode.cpp
    symmetric_aes.cpp
    mainwindow.ui
    ${TS_FILES})

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
  find_package(Qt6 REQUIRED COMPONENTS Core Test)

  qt_add_executable(SecureRune MANUAL_FINALIZATION ${PROJECT_SOURCES})
  # Define target properties for Android with Qt 6 as: set_property(TARGET
  # SecureRune APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
  # ${CMAKE_CURRENT_SOURCE_DIR}/android) For more information, see
  # https://doc.qt.io/qt-6/qt-add-executable.html#target-creation

  qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
else()
  if(ANDROID)
    add_library(SecureRune SHARED ${PROJECT_SOURCES})
    # Define properties for Android with Qt 5 after find_package() calls as:
    # set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
  else()
    add_executable(SecureRune ${PROJECT_SOURCES})
  endif()

  qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Core)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt${QT_VERSION_MAJOR}::Test)

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

file(GLOB CRYPTOPP_SOURCES ${CMAKE_SOURCE_DIR}/cryptopp/*.cpp
     ${CMAKE_SOURCE_DIR}/cryptopp/*.h)
add_library(cryptopp STATIC ${CRYPTOPP_SOURCES})
target_include_directories(cryptopp PUBLIC ${CMAKE_SOURCE_DIR}/cryptopp)

target_link_libraries(${PROJECT_NAME} PRIVATE cryptopp)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1. If
# you are developing for iOS or macOS you should consider setting an explicit,
# fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.SecureRune)
endif()
set_target_properties(
  SecureRune
  PROPERTIES ${BUNDLE_ID_OPTION} MACOSX_BUNDLE_BUNDLE_VERSION
             ${PROJECT_VERSION} MACOSX_BUNDLE_SHORT_VERSION_STRING
             ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR} MACOSX_BUNDLE
             TRUE WIN32_EXECUTABLE
             TRUE)

include(GNUInstallDirs)
install(
  TARGETS SecureRune
  BUNDLE DESTINATION .
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(QT_VERSION_MAJOR EQUAL 6)
  qt_finalize_executable(SecureRune)
endif()

if(APPLE)
  # Try to find macdeployqt in common Qt locations or in PATH
  find_program(
    MACDEPLOYQT_EXECUTABLE
    NAMES macdeployqt
    HINTS "$ENV{QT_DIR}" "$ENV{HOME}/Qt/6.9.3/macos/bin"
          "${CMAKE_PREFIX_PATH}/bin"
    PATHS)

  if(MACDEPLOYQT_EXECUTABLE)
    message(STATUS "Found macdeployqt: ${MACDEPLOYQT_EXECUTABLE}")
    # Run macdeployqt after building the bundle to copy Qt frameworks into the
    # .app
    add_custom_command(
      TARGET SecureRune
      POST_BUILD
      COMMAND "${MACDEPLOYQT_EXECUTABLE}" "$<TARGET_BUNDLE_DIR:SecureRune>"
      COMMENT "Running macdeployqt to bundle Qt frameworks into the app"
      VERBATIM)
  else()
    message(
      STATUS
        "macdeployqt not found; you can run it manually to bundle Qt frameworks (e.g. $HOME/Qt/6.9.3/macos/bin/macdeployqt)"
    )
  endif()
endif()
