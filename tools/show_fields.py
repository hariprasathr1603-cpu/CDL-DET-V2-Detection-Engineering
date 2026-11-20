import argparse
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

def extract_event_data(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    fields = {}
    system = root.find("e:System", ns)
    if system is not None:
        eid = system.find("e:EventID", ns)
        if eid is not None and eid.text:
            fields["EventID"] = eid.text.strip()
    event_data = root.find("e:EventData", ns)
    if event_data is not None:
        for data in event_data.findall("e:Data", ns):
            name = data.attrib.get("Name")
            if name and data.text:
                fields[name] = data.text.strip()
    return fields

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=r"C:\Users\hari9\Downloads\EVTX-ATTACK-SAMPLES")
    parser.add_argument("--limit-files", type=int, default=20)
    args = parser.parse_args()
    files = sorted(Path(args.path).rglob("*.evtx"))[:args.limit_files]
    eid_counts = Counter()
    samples = defaultdict(list)
    keys = ["EventID", "Image", "CommandLine", "ParentImage", "User", "TargetUserName"]
    for f in files:
        try:
            with Evtx(str(f)) as log:
                for rec in log.records():
                    try:
                        d = extract_event_data(rec.xml())
                    except Exception:
                        continue
                    eid_counts[d.get("EventID", "Unknown")] += 1
                    for k in keys:
                        v = d.get(k)
                        if v and len(samples[k]) < 3 and v not in samples[k]:
                            samples[k].append(v)
        except Exception:
            continue
    print("Event IDs:", dict(eid_counts.most_common(10)))
    for k in keys:
        print(f"\n[{k}]")
        for s in samples[k]:
            print("  ", s[:120])

if __name__ == "__main__":
    main()
