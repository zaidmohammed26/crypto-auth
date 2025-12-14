add_executable(client main.cpp)

target_include_directories(client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(client 
    PRIVATE 
    common_lib 
    Boost::headers
)