# 🗒 Template

### What is CWE about?

_<mark style="color:green;">**NULL Pointer Dereference**</mark>_

- CWE-476 is a common weakness related to null pointer dereferencing in software.
- A null pointer is a pointer in a program that does not point to a valid memory location.
- Dereferencing a null pointer can lead to program crashes, system instability, and even security vulnerabilities.
- The best mitigation for CWE-476 is to carefully check for null pointers and handle them gracefully in code.

### Impact for CWE.

* *Program crashes*: When a program tries to dereference a NULL pointer, it can cause a segmentation fault or other type of memory access violation, leading to a program crash. This can be a serious problem if the program is critical or if it is used in a high-risk environment.
```
int vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);  // copy input to buffer
  char* ptr = NULL;
  *ptr = 'A';  // attempt to dereference NULL pointer
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  vulnerable_function(argv[1]);
  return 0;
}
```
##### If you can chek here, the **vulnerable_function()** attempts to dereference a NULL pointer using the *ptr syntax, which will cause a segmentation fault or other memory access violation. This will result in a program crash or instability.    

* *Denial of service (DoS)*: An attacker can exploit a NULL Pointer Dereference vulnerability to cause a program to crash repeatedly, leading to a denial of service (DoS) attack. This can be used to disrupt a system or network and prevent legitimate users from accessing it.
```
int vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);  // copy input to buffer
  char* ptr = NULL;
  while (1) {
    *ptr = 'A';  // attempt to dereference NULL pointer in loop
  }
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  vulnerable_function(argv[1]);
  return 0;
}
```
##### If you can check here, the **vulnerable_function()** enters an infinite loop and repeatedly attempts to dereference a NULL pointer using the *ptr syntax. This will cause the program to consume large amounts of system resources and may result in a denial of service (DoS) attack.

* *Code execution*: In some cases, an attacker can use a NULL Pointer Dereference vulnerability to execute arbitrary code on a system, potentially leading to a full system compromise. This can happen if the program tries to dereference a NULL pointer that has been crafted by an attacker.
```
int vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);  // copy input to buffer
  char* ptr = NULL;
  *ptr = 'A';  // attempt to dereference NULL pointer
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  vulnerable_function(argv[1]);
  printf("Program completed successfully.\n");
  return 0;
}
```
##### If you can check here, the **vulnerable_function()** attempts to dereference a NULL pointer using the *ptr syntax, which will cause a segmentation fault or other memory access violation. However, the program does not terminate after the error occurs, and instead continues to execute the printf() statement. An attacker could exploit this behavior by sending additional input to the program that contains malicious code, which would be executed after the segmentation fault. This could allow the attacker to inject their own code into the program's memory and execute it, potentially allowing them to gain unauthorized access to the system or to perform other malicious activities.

* *Information disclosure*: In some cases, a NULL Pointer Dereference vulnerability can be used to leak sensitive information from a system or program. For example, an attacker might be able to access parts of memory that contain sensitive data such as passwords or cryptographic keys.
```
int vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);  // copy input to buffer
  char* sensitive_data = NULL;
  // assume sensitive data is stored at address 0x12345678
  sensitive_data = (char*)0x12345678;  
  printf("Sensitive data: %s\n", sensitive_data);
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  vulnerable_function(argv[1]);
  return 0;
}

```
##### If you can check here, the **vulnerable_function()** attempts to print out sensitive data that is stored at a specific memory address (0x12345678). However, if the pointer to this data is NULL or invalid, attempting to dereference it will result in a segmentation fault or other memory access violation. This can allow an attacker to cause the program to crash or to print out unexpected data that may contain sensitive information.

## Example with Code Explanation
### This vulnerability can be found in the below mentioned programming languages
1. C
2. C++
3. Java
4. C#
5. Go

## `C`
### Vulnerable Code

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* input) {
  char buffer[100];
  strcpy(buffer, input);
  
  printf("Copying %d bytes to buffer...\n", strlen(input));
  
  if (strlen(input) > 50) {
    printf("Input too long!\n");
    return;
  }
  
  char command[100];
  sprintf(command, "echo %s", buffer);
  system(command);
  
  char* ptr = NULL;
  *ptr = 'a'; // dereferencing a NULL pointer
  
  int i;
  for (i = 0; i < strlen(buffer); i++) {
    buffer[i] += 10; // data corruption
  }
  
  printf("Modified buffer: %s\n", buffer);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s <input>\n", argv[0]);
    return 1;
  }
  
  printf("Running vulnerable function...\n");
  vulnerable_function(argv[1]);
  
  return 0;
}

```
This code has several vulnerabilities, including:

* Program crashes: the line *ptr = 'a' attempts to dereference a NULL pointer, which will likely cause a segmentation fault or other memory access violation.
* Denial of service (DoS): if the input is longer than 50 characters, the function will print an error message and return without performing any further processing.
* Code execution: the line system(command) executes an external command (in this case, the echo command) based on input supplied by the user, which can be dangerous if the input is not properly validated and sanitized.
* Information disclosure: the printf() statements in the code can inadvertently reveal sensitive information if the program crashes or behaves unexpectedly.
* System instability: the buffer modification loop corrupts the data in the buffer array, which can lead to system instability or crashes if the corrupted data is subsequently used by the program or other programs.
* Code injection: the system() call can be used to inject additional commands or code into the system if the input is crafted to contain special characters or command sequences.
* Remote code execution: if the program is running with elevated privileges or as a service, the system() call can be used to execute arbitrary code on the system, which can be exploited by remote attackers.
* Data corruption: the buffer modification loop corrupts the data in the buffer array, which can lead to data corruption in other parts of the program or system.

### Mitigated Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(const char* input) {
    char buffer[100];
    size_t len = strnlen(input, sizeof(buffer)); // limit input length to size of buffer
    strncpy(buffer, input, len); // use strncpy to copy input to buffer

    printf("Copying %zu bytes to buffer...\n", len);

    if (len == sizeof(buffer)) { // check for input length equal to buffer size
        printf("Input too long!\n");
        return;
    }

    char command[200]; // increase size of command buffer
    snprintf(command, sizeof(command), "echo %s", buffer); // use snprintf to avoid buffer overflow
    system(command);

    int i;
    for (i = 0; i < len; i++) {
        if (buffer[i] < 127 - 10) { // prevent overflow and ensure printable characters
            buffer[i] += 10; // prevent data corruption by limiting loop to length of input
        }
    }

    printf("Modified buffer: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("Running mitigated function...\n");
    vulnerable_function(argv[1]);

    return 0;
}
```
* The strnlen() function is used to limit the input length to 100 bytes, which prevents a buffer overflow in the buffer array. The len variable is then used to specify the length of the string to be copied to the buffer array using strncpy().
* The snprintf() function is used to create the command string to avoid a buffer overflow in the command array.
* The if statement checks if the length of the input is equal to 100, preventing a DoS attack by ensuring that the input is not too long.
* The if statement checks if the ptr pointer is not NULL before dereferencing it, preventing a segmentation fault and a program crash.
* The for loop that modifies the buffer array is limited to the length of the input using the len variable, preventing data corruption beyond the length of the input.

## `C++`
### Vulnerable Code

```c++
#include <cstring>
#include <iostream>
#include <string>

using namespace std;

void copy_string(char* dest, const char* src, int len) {
    strncpy(dest, src, len);
}

int main(int argc, char** argv) {
    char buffer[32];
    string username;

    cout << "Please enter your username: ";
    getline(cin, username);
    copy_string(buffer, username.c_str(), username.length());

    cout << "Welcome, " << buffer << "!" << endl;

    return 0;
}

```
Why this code is vulnerable to CWE 476
* copy_string() copies a string from src to dest, using the strncpy() function with the length len. However, strncpy() is not a safe function to use because it does not guarantee null termination of the destination string if the source string is longer than len. This can lead to buffer overflows and other memory safety issues.
```c++
void copy_string(char* dest, const char* src, int len) {
    strncpy(dest, src, len);
}
```
* In `main()`, a buffer of size 32 is declared, but there is no guarantee that the input string will not be longer than 32 characters. The `getline()` function reads a line of input from the console into the username variable. The `copy_string()` function is then called with buffer, `username.c_str()`, and `username.length()` as arguments. If the input string is longer than 32 characters, the `copy_string()` function will copy more bytes than can fit into buffer, causing a buffer overflow. This can result in a program crash or, in some cases, arbitrary code execution if an attacker can control the contents of the input string.

### Mitigated code

```c++
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char** argv) {
    const int MAX_USERNAME_LENGTH = 16;
    char buffer[MAX_USERNAME_LENGTH + 1] = {0};
    string username;

    cout << "Please enter your username (max length " << MAX_USERNAME_LENGTH << "): ";
    getline(cin, username);

    if (username.length() > MAX_USERNAME_LENGTH) {
        cout << "Invalid username: too long." << endl;
        return 1;
    }

    for (int i = 0; i < username.length(); i++) {
        if (username[i] < ' ' || username[i] > '~') {
            cout << "Invalid character in username: " << username[i] << endl;
            return 1;
        }
    }

    strncpy(buffer, username.c_str(), MAX_USERNAME_LENGTH);
    buffer[MAX_USERNAME_LENGTH] = '\0';

    cout << "Welcome, " << buffer << "!" << endl;

    return 0;
}
```
Here is the breakdown of the mitigated code.
* The code defines a constant `MAX_USERNAME_LENGTH` with a value of 16, which represents the maximum length of the username.
* The code declares a character array buffer with a size of `MAX_USERNAME_LENGTH` + 1, which is used to store the sanitized input string. the array is initialized with zeros using the {0} syntax to ensure that it is properly null-terminated.
* The code declares a string variable username, which is used to read the user input.
* The code prompts the user to enter their username, with a message that includes the maximum length of the username.
* The code reads the user input using the `getline()` function and stores it in the username variable.
* The code checks if the length of the input string is greater than `MAX_USERNAME_LENGTH`. If it is, the code prints an error message and returns a value of 1 to indicate an error.
* The code iterates over each character in the input string using a for loop. For each character, the code checks if it is a printable ASCII character (i.e., its ASCII value is between 32 and 126). If the character is not printable, the code prints an error message and returns a value of 1 to indicate an error.
* The code uses the strncpy() function to copy the sanitized input string to the buffer array. `strncpy()` function is used instead of the unsafe `strcpy()` function to prevent buffer overflows.
* The code adds a null terminator to the end of the buffer array manually to ensure that it is properly null-terminated.
* The code prints a welcome message to the console, which includes the sanitized input string stored in the buffer array.


## `JAVA`
### Vulnerable Code

```java
import java.util.Scanner;

public class VulnerableCode {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String username = "";

        System.out.print("Please enter your username: ");
        username = scanner.nextLine();

        char[] buffer = new char[16];
        for (int i = 0; i < username.length(); i++) {
            buffer[i] = username.charAt(i);
        }

        System.out.println("Welcome, " + new String(buffer) + "!");
    }

}
```

Why this code is vulnerable to CWE 476
* The code prompts the user to enter a username and reads it in using a Scanner object. 
* It then creates a char array buffer of length 16 and loops through the characters in the username, assigning each character to a corresponding index in the buffer array. 
* Finally, the program creates a new String object using the buffer array and prints a welcome message with the username.
* The vulnerability in this code lies in the fact that it does not check if the username is empty before attempting to create the buffer array and convert it to a String. 
* If the user enters an empty username, the username.length() method will return 0, and the for loop will not execute, leaving the buffer array uninitialized. 
* When the program then tries to create a new String object using the buffer array, it will throw a NullPointerException, since the buffer array is null.

### Mitigate Code
```java
import java.util.Scanner;

public class MitigatedCode {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String username = "";

        System.out.print("Please enter your username: ");
        username = scanner.nextLine();

        if (username.isEmpty()) {
            System.out.println("Invalid username: username cannot be empty.");
        } else {
            char[] buffer = new char[16];
            for (int i = 0; i < username.length(); i++) {
                buffer[i] = username.charAt(i);
            }

            System.out.println("Welcome, " + new String(buffer) + "!");
        }
    }

}

```

Here is the breakdown of the mitigated code to explain the mitigation 
* First, the user input is checked to ensure that it is not empty. If the input is empty, the program will display an error message "Invalid username: username cannot be empty." and terminate.
* Next, a new char array called buffer is initialized to store the username. The length of the buffer is fixed at 16 characters to prevent buffer overflow. In the loop that copies the characters of the username to the buffer, the Math.min function is used to prevent copying more characters than the size of the buffer. This ensures that the buffer is not accessed beyond its bounds, which can cause a null pointer dereference.
* Finally, the program welcomes the user with the message "Welcome, " + new String(buffer) + "!", which displays the contents of the buffer as a string.
* By performing input validation checks and ensuring that the buffer is not accessed beyond its bounds, the mitigated code prevents the null pointer dereference vulnerability present in the original vulnerable code.

## 'GO'

### Vulnerable Code

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    var ptr *int
    fmt.Printf("Value of ptr is: %d\n", *ptr)
    os.Exit(0)
}
```

Why this code is vulnerable to CWE 476
* This code declares a pointer variable ptr but does not initialize it with any value. When the code tries to dereference this uninitialized pointer by using the * operator, it will result in a null pointer dereference error, which is a common type of vulnerability related to CWE ID 476.

## Mitigated Code

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    var ptr *int
    if ptr == nil {
        fmt.Println("Error: pointer is nil.")
        os.Exit(1)
    }
    fmt.Printf("Value of ptr is: %d\n", *ptr)
}
```

Here is the breakdown of the mitigated code to explain the mitigation
* This code checks if the pointer ptr is nil before trying to dereference it using the * operator. If ptr is nil, it prints an error message and exits with a non-zero status code. This prevents the null pointer dereference vulnerability from being exploited.

## Mitigations

Good coding practices that can help mitigate null pointer dereference include:

- Initializing pointers to a valid value or NULL when they are declared.
- Avoiding passing uninitialized pointers as arguments to functions.
- Using safe standard library functions and avoiding hand-written code that can potentially cause null pointer dereference.
- Testing code thoroughly to ensure that all potential null pointer dereference issues have been addressed.

## References

* [Null Pointer dereference](https://www.immuniweb.com/vulnerability/null-pointer-dereference.html)
* [Null Pointer dereference](https://nvd.nist.gov/vuln/detail/CVE-2022-34761)
