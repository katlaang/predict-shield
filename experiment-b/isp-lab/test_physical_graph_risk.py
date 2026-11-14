"""Contract tests are synthetic, physical CI records real SNMP + HTTP evidence."""
import unittest
from physical_graph_risk_pilot import synthetic_training_rows
from graph_risk_training import fit_and_evaluate
from predict_shield.graph_risk import predict_graph_risk

class PhysicalRiskContract(unittest.TestCase):
    def test_training_is_grouped_and_model_untrusted_for_dispatch(self):
        data=synthetic_training_rows()
        bundle,report=fit_and_evaluate(data)
        self.assertEqual(report["train_groups"],8)
        self.assertEqual(report["test_groups"],2)
        row=data[0]
        prediction=predict_graph_risk(bundle,row["graph"],row["asset_id"],
                            critical_services=tuple(row["critical_services"]),
                            confirmed_exposure=row["confirmed_exposure"])
        self.assertFalse(prediction["decision_authorized"])
        self.assertFalse(prediction["probability_calibrated"])
if __name__=="__main__":unittest.main()
