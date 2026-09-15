"""SentinelFloor edge tier.

Runs on-premises next to the recorder. Video frames never leave this process: pose
keypoints are extracted and the frame is discarded immediately. What crosses the network
to the core service is a small JSON document containing a score and derived numeric
features, signed with a per-camera key.

That boundary is the whole privacy argument for the system, so it is enforced in code by
:mod:`edge.privacy` rather than left as a convention.
"""

__version__ = "0.1.0"
