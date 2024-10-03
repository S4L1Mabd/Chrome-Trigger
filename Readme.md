<!--   my-ticker -->    
<!-- &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;[![Typing SVG](https://readme-typing-svg.herokuapp.com?color=%F0E68C&center=true&vCenter=true&width=250&lines=S4L1M+MalWareDev"")](https://git.io/typing-svg) -->

<p align="center">
  <a href="https://git.io/typing-svg">
    <img src="https://readme-typing-svg.herokuapp.com?color=%F0E68C&center=true&vCenter=true&width=250&lines=S4L1M+MalWareDev" alt="Typing SVG">
  </a>
</p>

# Chrometrigger: Remote Shellcode Injection with Payload Encryption

This project focuses on remote shellcode injection targeting Chrome browser processes, with added payload encryption to bypass Windows Defender and other security systems. The encryption methods used include AES and XOR for obfuscation and decryption of the shellcode before execution.

## Features

- **AES Encryption**: A strong encryption standard, used to secure the payload and evade detection.
- **XOR Encryption**: A simple, yet effective technique for basic payload obfuscation, commonly seen in malware development.
- **Shellcode Injection**: Injects shellcode into a remote Chrome process on the target machine after decryption.
- **Windows Defender Evasion**: Utilizes payload encryption to evade detection and prevent the payload from being flagged as malicious.

## Technical Overview

### 1. Payload Encryption
- **AES**: Encrypts the shellcode using a secure key and initialization vector (IV) to prevent detection by antivirus solutions.
- **XOR**: A lightweight obfuscation technique that adds an extra layer of protection by scrambling the shellcode before injection.

### 2. Decryption
- **AES and XOR**: Both encryption methods are supported for decrypting the payload in memory before injection into the target process.

### 3. Process Injection
- The encrypted shellcode is injected into a Chrome process remotely, allowing the execution of the payload on the target machine.

## Usage

1. **Clone the Repository**: Download the project from GitHub.

    ```bash
    git clone https://github.com/S4L1Mabd/Chrometrigger.git
    ```

2. **Compile the Code**: Use Visual Studio or a compatible compiler to build the executable.

3. **Run the Injection And follow the instructions **: Inject the encrypted payload into a target Chrome process.

    ```bash
    Chrometrigger.exe 
    ```

4. **Decryption**: The injected payload is decrypted in memory, allowing it to execute in the target process.

### Prerequisites

- **Visual Studio**: For compiling and running the project.
- **Windows OS**: The project is developed and tested on Windows systems.
- **Administrator Privileges**: Required for process injection and shellcode execution.

## Disclaimer

This project is intended for educational and research purposes only. The misuse of this code for illegal activities is prohibited and can result in serious legal consequences. Please use responsibly.

## License

All rights reserved.

---

### Hashtags
- #MalwareDevelopment
- #ShellcodeInjection
- #PayloadEncryption
- #AES
- #XOREncryption
- #WindowsDefenderEvasion
- #Cybersecurity
