In this update, missing method-specific fix information was added in accordance with the new guidelines established in [`contributing_cwe_bench_java.md`](contributing_cwe_bench_java.md). 

The new tests established at [`data/tests`](data/tests) enforce these guidelines. However, there are a few data points from the original benchmark that are not in accordance with these guidelines, which we have chosen to keep.

### Known Exceptions

| ID | Benchmark / CVE | Commit Hash | File Path |
| :--- | :--- | :--- | :--- |
| **974** | `nahsra__antisamy_CVE-2017-14735_1.5.6` | `82da009e733a989a57190cd6aa1b6824724f6d36` | `src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java` |
| **975** | `nahsra__antisamy_CVE-2017-14735_1.5.6` | `82da009e733a989a57190cd6aa1b6824724f6d36` | `src/main/java/org/owasp/validator/html/scan/AntiSamySAXScanner.java` |
| **1062** | `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE` | `a087e828a63edf0932e4eecf174cf816cbe6a58a` | `web/src/main/java/org/springframework/security/web/firewall/DefaultHttpFirewall.java` |
| **1100** | `x-stream__xstream_CVE-2013-7285_1.4.6` | `6344867dce6767af7d0fe34fb393271a6456672d` | `src/java/com/thoughtworks/xstream/converters/extended/FileConverter.java` |
| **1104** | `x-stream__xstream_CVE-2020-26217_1.4.14` | `0fec095d534126931c99fd38e9c6d41f5c685c1a` | `src/java/com/thoughtworks/xstream/converters/extended/FileConverter.java` |

---

> [!NOTE]
> If there are any additional issues with `fix_info.csv`, please open an issue so we can fix it!
