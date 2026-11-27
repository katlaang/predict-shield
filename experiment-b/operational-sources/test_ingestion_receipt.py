"""Synthetic P1 durability and ground-truth refusal tests; not real datasets."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ingestion_receipt import audit_file, write_receipt
from normalize import normalized_rows

KEY=b"deterministic-unit-test-only-hmac-secret-12345"


class P1IngestionReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def valid(self, dataset="lanl-auth"):
        text=("1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success\n"
              "2,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Fail\n")
        if dataset=="ugr16-flow":
            text=("te,td,sa,da,sp,dp,pr,flg,fwd,stos,pkt,byt\n"
                  "2016-04-01 00:00:00,0.5,192.0.2.1,198.51.100.2,50000,443,6,....,0,0,3,144\n")
        if dataset=="mawilab-annotation":
            text=("anomalyID,srcIP,srcPort,dstIP,dstPort,taxonomy,heuristic,distance,nbDetectors,label\n"
                  "A13,192.0.2.1,33001,198.51.100.2,443,DDoS,heur,1.25,5,anomalous\n")
        src=self.root/(dataset+".csv")
        src.write_text(text)
        rows,_=normalized_rows(src,dataset=dataset,
                     expected_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),
                     pseudonym_key=KEY,max_records=100)
        output=self.root/(dataset+"-normalized.jsonl")
        output.write_text("".join(json.dumps(x)+"\n" for x in rows))
        return output

    def test_three_publisher_adapters_emit_durable_unknown_truth_receipts(self):
        for dataset in ("lanl-auth","ugr16-flow","mawilab-annotation"):
            path=self.valid(dataset)
            r=audit_file(path)
            self.assertEqual(r["dataset"],dataset)
            self.assertGreater(r["record_count"],0)
            self.assertEqual(r["labels"]["attack_publisher_scenario"],0)
            self.assertFalse(r["independent_attack_ground_truth_established"])
            dest=self.root/(dataset+".receipt.json")
            write_receipt(r,dest)
            self.assertEqual(json.loads(dest.read_text()),r)
            with self.assertRaises(FileExistsError):
                write_receipt(r,dest)

    def test_crashed_temporary_receipt_is_not_accepted_as_committed(self):
        path=self.valid()
        receipt=audit_file(path)
        interrupted=self.root/".p1-admission-UNFINISHED.tmp"
        interrupted.write_text('{"schema":"incomplete"')
        dest=self.root/"committed.json"
        write_receipt(receipt,dest)
        self.assertEqual(json.loads(dest.read_text())["record_count"],2)
        self.assertEqual(interrupted.read_text(),'{"schema":"incomplete"')

    def test_duplicate_line_and_unverified_attack_claim_rejected(self):
        path=self.valid()
        records=[json.loads(x) for x in path.read_text().splitlines()]
        records[1]["source_line"]=records[0]["source_line"]
        path.write_text("".join(json.dumps(x)+"\n" for x in records))
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            audit_file(path)
        records[1]["source_line"]=2
        records[0]["verified_attack"]=True
        path.write_text("".join(json.dumps(x)+"\n" for x in records))
        with self.assertRaisesRegex(ValueError,"verified attack"):
            audit_file(path)

    def test_missing_original_provenance_fails_closed(self):
        path=self.valid()
        records=[json.loads(x) for x in path.read_text().splitlines()]
        records[0].pop("source_sha256")
        path.write_text("".join(json.dumps(x)+"\n" for x in records))
        with self.assertRaisesRegex(ValueError,"original source-line integrity"):
            audit_file(path)

    def test_no_silent_benign_labeling_for_network_flows(self):
        path=self.valid("ugr16-flow")
        records=[json.loads(x) for x in path.read_text().splitlines()]
        records[0]["label"]="benign"
        path.write_text(json.dumps(records[0])+"\n")
        with self.assertRaisesRegex(ValueError,"silently reclassified"):
            audit_file(path)


if __name__=="__main__":
    unittest.main()
