System oriented programming project of second year of Computer Science of an encrypted messaging application copying a bit how the application Signal works but without all the securities needed to be a proper replacement for the real one.

This project has been made with my teammate @dayan9265 during the 4th semester of Computer Science at EPFL.

You can reuse all the code for all type of uses but becareful with the licensing of libmongoose if you also want to use it in your project.

Dependencies needed :
- mongoose (given and compiled with the Makefile)  

Using your package manager :
- openssh-client
- libssl-dev
- libcurl4-openssl-dev
- libjson-c-dev
- libasan

IMPORTANT:
- Indicate the local variable using command : export LD_LIBRARY_PATH="${PWD}/libmongoose"

The only "big" issue is the error system between the server and the client can be impresized and not send the correct error message to the client.
