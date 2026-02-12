# Styx
This is malware designed to steal IP addresses and send them to Google Colab.
Main features:
• Steals the victim’s IP address
• Uses RC4/AES encryption to disguise the payload
• Bypasses antivirus software through dynamic key generation and obfuscation
• Sends data to a remote server (Google Colab webhook)

Concealment methods:
• Encrypts strings and API keys
• Generates an RC4 key from the PEB (Process Environment Block)
• Checks for debuggers / VMs
• Uses direct syscalls
• Cleans traces after execution

He is one of the "Reservoirs of Hell" project
