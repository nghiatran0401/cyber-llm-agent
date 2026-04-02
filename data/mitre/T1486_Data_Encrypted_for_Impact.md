# T1486 - Data Encrypted for Impact

**Tactic:** Impact
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1486

## Description

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.

In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted (and often renamed and/or tagged with specific file markers). Adversaries may need to first employ other behaviors, such as File and Directory Permissions Modification or System Shutdown/Reboot, in order to unlock and/or gain access to manipulate these files. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR. Adversaries may also encrypt virtual machines hosted on ESXi or other hypervisors. 

To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares. Encryption malware may also leverage Internal Defacement, such as changing victim wallpapers or ESXi server login messages, or otherwise intimidate victims by sending ransom notes or other messages to connected printers (known as "print bombing").

In cloud environments, storage objects within compromised accounts may also be encrypted. For example, in AWS environments, adversaries may leverage services such as AWS’s Server-Side Encryption with Customer Provided Keys (SSE-C) to encrypt data.

## Detection

### Detection Analytics

**Analytic 0602**

High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell.

**Analytic 0603**

Encryption via custom or open-source tools (e.g., openssl, gpg, aescrypt) recursively targeting user or system directories. Also includes overwrite of existing data and ransom note drops.

**Analytic 0604**

Userland or kernel-level ransomware encrypting user files (Documents, Desktop) using `srm`, `gpg`, or compiled payloads. Often correlated with ransom note creation in multiple directories.

**Analytic 0605**

Ransomware encrypts .vmdk, .vmx, .log, or VM config files in VMFS datastores. May rename to .locked or delete/overwrite with encrypted versions. Often correlates with shell commands run through `dcui`, SSH, or vSphere.

**Analytic 0606**

Encryption of cloud storage objects (e.g., S3 buckets) via Server-Side Encryption (SSE-C) or by replacing objects with encrypted variants. May include API patterns like PutObject with SSE-C headers.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. In AWS environments, create an IAM policy to restrict or block the use of SSE-C on S3 buckets.

### M1053 - Data Backup

Consider implementing IT disaster recovery plans that contain procedures for regularly taking and testing data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. Consider enabling versioning in cloud environments to maintain backup copies of storage objects.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1129 - Akira

Akira can encrypt victim filesystems for financial extortion purposes including through the use of the ChaCha20 and ChaCha8 stream ciphers.

### S1194 - Akira _v2

The Akira _v2 encryptor targets the `/vmfs/volumes/` path by default and can use the rust-crypto 0.2.36 library crate for the encryption processes.

### S1133 - Apostle

Apostle creates new, encrypted versions of files then deletes the originals, with the new filenames consisting of a random GUID and ".lock" for an extension.

### S0640 - Avaddon

Avaddon encrypts the victim system using a combination of AES256 and RSA encryption schemes.

### S1053 - AvosLocker

AvosLocker has encrypted files and network resources using AES-256 and added an `.avos`, `.avos2`, or `.AvosLinux` extension to filenames.

### S0638 - Babuk

Babuk can use ChaCha8 and ECDH to encrypt data.

### S0606 - Bad Rabbit

Bad Rabbit has encrypted files and disks using AES-128-CBC and RSA-2048.

### S0570 - BitPaymer

BitPaymer can import a hard-coded RSA 1024-bit public key, generate a 128-bit RC4 key for each file, and encrypt the file in place, appending <code>.locked</code> to the filename.

### S1070 - Black Basta

Black Basta can encrypt files with the ChaCha20 cypher and using a multithreaded process to increase speed. Black Basta has also encrypted files while the victim system is in safe mode, appending `.basta` upon completion.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware is a ransomware variant associated with BlackByte operations.

### S1180 - BlackByte Ransomware

BlackByte Ransomware is ransomware using a shared key across victims for encryption.

### S1068 - BlackCat

BlackCat has the ability to encrypt Windows devices, Linux devices, and VMWare instances.

### S1096 - Cheerscrypt

Cheerscrypt can encrypt data on victim machines using a Sosemanuk stream cipher with an Elliptic-curve Diffie–Hellman (ECDH) generated key.

### S0611 - Clop

Clop can encrypt files using AES, RSA, and RC4 and will add the ".clop" extension to encrypted files.

### S0575 - Conti

Conti can use <code>CreateIoCompletionPort()</code>, <code>PostQueuedCompletionStatus()</code>, and <code>GetQueuedCompletionPort()</code> to rapidly encrypt files, excluding those with the extensions of .exe, .dll, and .lnk. It has used a different AES-256 encryption key per file with a bundled RAS-4096 public encryption key that is unique for each victim. Conti can use “Windows Restart Manager” to ensure files are unlocked and open for encryption.

### S0625 - Cuba

Cuba has the ability to encrypt system data and add the ".cuba" extension to encrypted files.

### S1033 - DCSrv

DCSrv has encrypted drives using the core encryption mechanism from DiskCryptor.

### S0616 - DEATHRANSOM

DEATHRANSOM can use public and private key pair encryption to encrypt files for ransom payment.

### S1111 - DarkGate

DarkGate can deploy follow-on ransomware payloads.

### S0659 - Diavol

Diavol has encrypted files using an RSA key though the `CryptEncrypt` API and has appended filenames with ".lock64".

### S0605 - EKANS

EKANS uses standard encryption library functions to encrypt files.

### S0554 - Egregor

Egregor can encrypt all non-system files using a hybrid AES-RSA algorithm prior to displaying a ransom note.

### S1247 - Embargo

Embargo has the ability to encrypt files with the ChaCha20 and Curve25519 cryptographic algorithms. Embargo also has the ability to encrypt system data and add a random six-letter extension consisting of hexadecimal characters such as ".b58eeb" or “.3d828a” to encrypted files.

### S0618 - FIVEHANDS

FIVEHANDS can use an embedded NTRU public key to encrypt data for ransom.

### S0617 - HELLOKITTY

HELLOKITTY can use an embedded RSA-2048 public key to encrypt victim data for ransom.

### S1139 - INC Ransomware

INC Ransomware can encrypt data on victim systems, including through the use of partial encryption and multi-threading to speed encryption.

### S0389 - JCry

JCry has encrypted files and demanded Bitcoin to decrypt those files.

### S0607 - KillDisk

KillDisk has a ransomware component that encrypts files with an AES key that is also RSA-1028 encrypted.

### S1199 - LockBit 2.0

LockBit 2.0 can use standard AES and elliptic-curve cryptography algorithms to encrypt victim data.

### S1202 - LockBit 3.0

LockBit 3.0 can encrypt targeted data using the AES-256, ChaCha20, or RSA-2048 algorithms.

### S0372 - LockerGoga

LockerGoga has encrypted files, including core Windows OS files, using RSA-OAEP MGF1 and then demanded Bitcoin be paid for the decryption key.

### S0449 - Maze

Maze has disrupted systems by encrypting files on targeted machines, claiming to decrypt files if a ransom payment is made. Maze has used the ChaCha algorithm, based on Salsa20, and an RSA algorithm to encrypt files.

### S1244 - Medusa Ransomware

Medusa Ransomware has encrypted files using AES-256 encryption, which then appends the file extension “.medusa” to encrypted files and leaves a ransomware note named “!READ_ME_MEDUSA!!!.txt.”

### S0576 - MegaCortex

MegaCortex has used the open-source library, Mbed Crypto, and generated AES keys to carry out the file encryption process.

### S1191 - Megazord

Megazord can encrypt files on targeted Windows hosts leaving them with a  ".powerranges" file extension.

### S1137 - Moneybird

Moneybird targets a common set of file types such as documents, certificates, and database files for encryption while avoiding executable, dynamic linked libraries, and similar items.

### S0457 - Netwalker

Netwalker can encrypt files on infected machines to extort victims.

### S0368 - NotPetya

NotPetya encrypts user files and disk structures like the MBR with 2048-bit RSA.

### S0556 - Pay2Key

Pay2Key can encrypt data on victim's machines using RSA and AES algorithms in order to extort a ransom payment for decryption.

### S1162 - Playcrypt

Playcrypt encrypts files on targeted hosts with an AES-RSA hybrid encryption, encrypting every other file portion of 0x100000 bytes.

### S1058 - Prestige

Prestige has leveraged the CryptoPP C++ library to encrypt files on target systems using AES and appended filenames with `.enc`.

### S0654 - ProLock

ProLock can encrypt files on a compromised host with RC6, and encrypts the key with RSA-1024.

### S0583 - Pysa

Pysa has used RSA and AES-CBC encryption algorithm to encrypt a list of targeted file extensions.

### S1242 - Qilin

Qilin can use AES-256 or ChaCha20 for domain-wide encryption of victim servers and workstations and RSA-4096 or RSA-2048 to secure generated encryption keys.

### S0496 - REvil

REvil can encrypt files on victim systems and demands a ransom to decrypt the files.

### S1150 - ROADSWEEP

ROADSWEEP can RC4 encrypt content in blocks on targeted systems.

### S0481 - Ragnar Locker

Ragnar Locker encrypts files on the local machine and mapped drives prior to displaying a note demanding a ransom.

### S1212 - RansomHub

RansomHub can use Elliptic Curve Encryption to encrypt files on targeted systems. RansomHub can also skip content at regular intervals (ex. encrypt 1 MB, skip 3 MB) to optomize performance and enable faster encryption for large files.

### S0400 - RobbinHood

RobbinHood will search for an RSA encryption key and then perform its encryption process on the system files.

### S1073 - Royal

Royal uses a multi-threaded encryption process that can partially encrypt targeted files with the OpenSSL library and the AES256 algorithm.

### S0446 - Ryuk

Ryuk has used a combination of symmetric (AES) and asymmetric (RSA) encryption to encrypt files. Files have been encrypted with their own AES key and given a file extension of .RYK. Encrypted directories have had a ransom note of RyukReadMe.txt written to the directory.

### S0370 - SamSam

SamSam encrypts victim files using RSA-2048 encryption and demands a ransom be paid in Bitcoin to decrypt those files.

### S0639 - Seth-Locker

Seth-Locker can encrypt files on a targeted system, appending them with the suffix .seth.

### S0140 - Shamoon

Shamoon has an operational mode for encrypting data instead of overwriting it.

### S1178 - ShrinkLocker

ShrinkLocker uses the legitimate BitLocker application to encrypt victim files for ransom.

### S0242 - SynAck

SynAck encrypts the victims machine followed by asking the victim to pay a ransom.

### S0595 - ThiefQuest

ThiefQuest encrypts a set of file extensions on a host, deletes the original files, and provides a ransom note with no contact information.

### S0366 - WannaCry

WannaCry encrypts user files and demands that a ransom be paid in Bitcoin to decrypt those files.

### S0612 - WastedLocker

WastedLocker can encrypt data and leave a ransom note.

### S0658 - XCSSET

XCSSET performs AES-CBC encryption on files under <code>~/Documents</code>, <code>~/Downloads</code>, and
<code>~/Desktop</code> with a fixed key and renames files to give them a <code>.enc</code> extension. Only files with sizes 
less than 500MB are encrypted.

### S0341 - Xbash

Xbash has maliciously encrypted victim's database systems and demanded a cryptocurrency ransom be paid.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0015 - C0015

During C0015, the threat actors used Conti ransomware to encrypt a compromised network.

### C0018 - C0018

During C0018, the threat actors used AvosLocker ransomware to encrypt files on the compromised network.

### C0038 - HomeLand Justice

During HomeLand Justice, threat actors used ROADSWEEP ransomware to encrypt files on targeted systems.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors deployed ransomware including 4L4MD4R and Warlock.
