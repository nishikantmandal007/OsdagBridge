import os as _os
import sys as _sys
import warnings as _warnings


def _register_conda_dll_directories():
    """Add the active conda environment's native DLL folders to the Windows DLL
    search path.

    Installer-launched apps (e.g. a conda-constructor build) do not "activate"
    the environment, so ``<prefix>/Library/bin`` — where the BLAS/LAPACK backend
    (MKL ``mkl_rt``/``libblas`` or OpenBLAS) lives — is absent from the DLL search
    path. numpy/scipy/openseespy then import fine but crash the whole process
    with a native ``ERROR_MOD_NOT_FOUND`` (``0xc06d007f``) the first time they
    delay-load LAPACK (e.g. ``numpy.linalg.lstsq`` during grillage meshing).
    Registering these directories before numpy is imported prevents that crash.
    No-op on non-Windows platforms and in already-activated environments.
    """
    if _os.name != "nt":
        return
    prefix = _sys.prefix
    candidates = [
        _os.path.join(prefix, "Library", "bin"),
        _os.path.join(prefix, "Library", "mingw-w64", "bin"),
        _os.path.join(prefix, "Library", "usr", "bin"),
        _os.path.join(prefix, "DLLs"),
        prefix,
    ]
    path_entries = _os.environ.get("PATH", "").split(_os.pathsep)
    for path in candidates:
        if not _os.path.isdir(path):
            continue
        try:
            _os.add_dll_directory(path)
        except (OSError, AttributeError):
            pass
        # Some native libraries resolve dependents via PATH rather than the
        # secure add_dll_directory list; prepend for completeness.
        if path not in path_entries:
            _os.environ["PATH"] = path + _os.pathsep + _os.environ.get("PATH", "")
            path_entries.insert(0, path)


_register_conda_dll_directories()

import numpy as np  # re-exported: tests and users access ospgrillage.np
import openseespy.opensees as ops  # re-exported: tests and users access ospgrillage.ops

# NOTE: ``opsvis`` and ``matplotlib.pyplot`` are intentionally NOT imported here.
# They pull matplotlib (+ backends) onto the import path of every consumer that
# merely ``import ospgrillage`` — a large startup cost paid even when no plot is
# ever drawn. They remain reachable as ``ospgrillage.opsv`` / ``ospgrillage.plt``
# via the lazy ``__getattr__`` below (imported+cached on first access), so the
# public re-exports behave exactly as before.
from ospgrillage.utils import *
from ospgrillage.mesh import *
from ospgrillage.load import *
from ospgrillage.material import *
from ospgrillage.members import *
from ospgrillage.osp_grillage import *
from ospgrillage.postprocessing import *

__version__ = "0.6.0"

# Explicit public API — everything a user should access from `import ospgrillage`
__all__ = [
    "__version__",
    # Grillage model
    "OspGrillage",
    "OspGrillageBeam",
    "OspGrillageShell",
    "create_grillage",
    # Members & sections
    "GrillageMember",
    "Section",
    "create_member",
    "create_section",
    # Materials
    "Material",
    "create_material",
    # Loads
    "LoadCase",
    "LoadModel",
    "Loads",
    "MovingLoad",
    "NodalLoad",
    "NodeForces",
    "PatchLoading",
    "Path",
    "PointLoad",
    "LineLoading",
    "LoadVertex",
    "LoadPoint",  # deprecated alias for LoadVertex
    "CompoundLoad",
    "Line",
    "ShapeFunction",
    "create_load_vertex",
    "create_load",
    "create_load_case",
    "create_load_model",
    "create_moving_load",
    "create_moving_path",
    "create_compound_load",
    # Mesh / geometry
    "Point",
    "Mesh",
    "create_point",
    # Post-processing & plotting
    "Envelope",
    "Members",
    "PostProcessor",
    "create_envelope",
    "model_proxy_from_results",
    "plot_force",
    "plot_bmd",
    "plot_sfd",
    "plot_tmd",
    "plot_def",
    "plot_model",
    "plot_srf",
]


# ---------------------------------------------------------------------------
# Lazy access for the heavy plotting re-exports
# ---------------------------------------------------------------------------
# ``ospgrillage.plt`` and ``ospgrillage.opsv`` remain part of the public surface
# (used by og.plot_model / og.plt.gcf()), but matplotlib.pyplot and opsvis are
# only imported the first time one of them is accessed, then cached into the
# module namespace so subsequent lookups skip this hook. Behaviour is identical
# to the previous eager re-exports (no warning) — just deferred.
def __getattr__(name):
    if name == "plt":
        import matplotlib.pyplot as _plt

        globals()["plt"] = _plt
        return _plt
    if name == "opsv":
        import opsvis as _opsv

        globals()["opsv"] = _opsv
        return _opsv
    if name == "opsplt":
        _warnings.warn(
            "og.opsplt is deprecated — use og.plot_model() for mesh visualisation. "
            "vfo/opsplt will be removed in a future version.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            import vfo.vfo as _opsplt

            return _opsplt
        except ImportError:
            raise ImportError(
                "vfo is no longer a required dependency. "
                "Install it with: pip install vfo"
            ) from None
    raise AttributeError(f"module 'ospgrillage' has no attribute {name!r}")
