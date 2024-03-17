# Example Use Cases

The samples provided in `samples.zip` can be used to test the plugin and reproduce the results. To unpack, use the password "infected" or the following command:

```bash
$ unzip -P infected samples.zip
```

In particular, the sample `triton_inject.bin` is worth a closer look.


## Triton

The [Triton malware](https://en.wikipedia.org/wiki/Triton_(malware)) includes a PowerPC stub `triton_inject.bin`, containing 23 functions with custom logic. LLM-based function naming quickly sorts these functions, notably identifying those doing data copying and implementing complex code patterns.


## Statically-linked Executables

Distinguishing between user and library code in statically-linked executables poses a challenge. However, specific API calls often fall among the [most-called functions](https://synthesis.to/2023/08/02/api_functions.html) within a binary. By filtering for these functions and consulting an LLM, it's possible to automatically identify standard functions like `memcpy` and `strlen`. Detailed examples will be provided in future updates.