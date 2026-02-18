# iOS and MacOS have a security feature called Pointer Authentication (PAC) that is designed to prevent certain types of memory corruption attacks.

###  Arm64e is an extension of the Arm64 architecture that includes support for PAC. It was introduced in Apple's A12 Bionic chip and is used in newer iOS devices.
### Arm64 is the standard 64-bit architecture, they can support PAC but it is not required and not all Arm64 devices will have PAC support.


A Mach-O contains 2 things of note to this discussion:
* Internal pointers
  * For example, a pointer from __objc_selrefs to the selector literal in another section
* Pointer authentication codes (PACs)
  * For example, the return address of a function call, which is protected by a PAC to prevent return-oriented programming (ROP) attacks

* My understanding
  * when we load a binary into strongarm it needs to "fix up" the internal pointers and some point at external systems 
  * however due to arm64e being used these days in new binaries, there are also PACs (Pointer Authentication Codes).
  * these PAC's contain extra fields in the metadata and thats why strongarm parsing doesnt work on arm64e 
### Researching into PAC

* Internal Pointer Structure
* PAC Assembly Instructions
  * pacibsp
  * paciza
  * 