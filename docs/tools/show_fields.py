fields = [
    ("EventID", "4688 / 1"),
    ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("CommandLine", r"powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="),
    ("ParentImage", r"C:\Windows\System32\cmd.exe"),
    ("User", r"CORP\analyst01"),
]

print("Key Log Fields & Sample Values:")
print("-" * 75)
for name, sample in fields:
    print(f"{name:<15} | Sample: {sample}")