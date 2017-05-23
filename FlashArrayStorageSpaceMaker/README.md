## Motive
Linux file systems (ext, xfs) are not meant to use a CAS (Content-Aware Storage) such as Dell EMC XtremeIO All-Flash Array. 

While a CAS can effectively serve its main purpose, storage, it has inaccurate capacity (free/used) information because of the way they store blocks of memory and the way Linux distributions allocate files. 

### A Content-Aware Storage (CAS) optimization works as follows
> The technology identifies how a given file is structured and then selects from a library of more than 100 algorithms the one that is most effective for the targeted data set. Even if the file has never before been identified, and there is no content-specific compressor, the technology will infer information about the structure and nature of the contents to select the most effective data reduction algorithm.
http://www.dell.com/learn/us/en/555/solutions/deduplication-content-aware

In other words, the CAS will try to avoid duplicating data and will instead create "pointers" to other blocks of data when redundant blocks are being stored. 

For example: if a linux distribution filesystem allocated 4 blocks (consisting of only zeros) in memory, the CAS will only store 1 block consisting of only zeros and will create 4 references to it. That way, the CAS is saving capacity.


## Problem
When a file gets deleted in some Linux file systems what actually happens is that the path to the file stops existing, and therefore, the pointer to the file is destructed. However, the set of blocks of zeroes and ones will stay there unchanged until replaced by other files. So if you had a 2GB movie within your files that gets deleted later on, the CAS would still think it has to keep the blocks that the big file consisted of as those blocks of zeroes and ones technically still exist. This is the reason why innacurate capacity information will always be shown in a CAS used by Linux distributions.


## Solution
Perl script that writes zeros to unused blocks of memory in Linux. 

How? Determine the amount of free space and create a file of only zeroes that is almost as big as the amount of free space and delete this file afterwards.
This would make the file system allocate blocks of zeroes in unused blocks thoughout the entire partition (remember that these unused blocks are holding garbage, sets of zeroes and ones that are not really files anymore).

Why? All these blocks of only zeroes will be stored as only one block of zeroes in the CAS. Therefore, the CAS will show a more accurate value of its free space if the script is run in all the virtual machines that use it as storage.


### Process
1. Checks the output of lsmod for the presence of vmw_pvscsi to determine if the computer is a virtual machine. If it is not, exit the program

2. Gets all local file systems

3. Gets available and use% space on each file system

4. If the available space is less than 1Gb or the use% is over 95%, skip

5. If the available space is more than 1Gb, write -a file of- zeroes to the file system for all but 1Gb of free space (deletes file afterwards).

