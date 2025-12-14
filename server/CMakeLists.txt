add_executable(server main.cpp)

target_include_directories(server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(server 
    PRIVATE 
    common_lib 
    Boost::headers
)