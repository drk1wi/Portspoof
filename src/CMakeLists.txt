# Define sources
set(SOURCES
        Configuration.cpp
        connection.cpp
        Fuzzer.cpp
        Portspoof.cpp
        Server.cpp
        Revregex.cpp
        Utils.cpp
)

# Define headers (for IDE grouping)
set(HEADERS
        Configuration.h
        connection.h
        Fuzzer.h
        Server.h
        Revregex.h
        Utils.h
)

# Create executable
add_executable(portspoof ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(portspoof PRIVATE Threads::Threads)

# Add compile definition for configuration directory
# In Autotools this was passed via -DCONFDIR='"$(sysconfdir)"'
# For CMake, we can default to /etc unless specified
if (NOT DEFINED CONFDIR)
    set(CONFDIR "/etc")
endif ()
target_compile_definitions(portspoof PRIVATE CONFDIR="${CONFDIR}")

# Install rules
install(TARGETS portspoof DESTINATION bin)
