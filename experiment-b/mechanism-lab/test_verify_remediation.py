import unittest
from pathlib import Path

import verify_remediation as vr


class VerifyRemediationRegistrationTests(unittest.TestCase):
    """These check that the pilot's registrations are well-formed, not that
    `mvn`/Docker actually succeed: that needs a live Docker daemon and real
    network access to Maven Central, which this suite does not assume.
    """

    def test_resolution_targets_the_project_build_image(self):
        self.assertIn("docker", vr.RESOLUTION.command)
        self.assertIn(vr._MAVEN_IMAGE, vr.RESOLUTION.command)
        self.assertIn("dependency:resolve", vr.RESOLUTION.command)
        self.assertEqual(vr.RESOLUTION.assertion, "dependency_resolution_ok:mechanism-lab")

    def test_regression_targets_the_project_build_image_and_real_tests(self):
        self.assertIn("docker", vr.REGRESSION.command)
        self.assertIn(vr._MAVEN_IMAGE, vr.REGRESSION.command)
        self.assertIn("test", vr.REGRESSION.command)
        self.assertEqual(vr.REGRESSION.assertion, "no_regression:mechanism-lab")

    def test_java_dir_is_the_real_maven_project(self):
        self.assertTrue((vr.JAVA_DIR / "pom.xml").is_file())
        self.assertTrue((vr.JAVA_DIR / "Dockerfile").is_file())

    def test_build_image_matches_the_projects_own_dockerfile(self):
        dockerfile = (vr.JAVA_DIR / "Dockerfile").read_text()
        self.assertIn(vr._MAVEN_IMAGE, dockerfile)


if __name__=="__main__": unittest.main()
