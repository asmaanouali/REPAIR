/-
# IRSAM.Binders.Subprocess

Lean encoding of the shell-family binders (``binders/python_subprocess.yaml``,
``binders/java_processbuilder.yaml``, ``binders/jsts_child_process.yaml``).
-/
import IRSAM.Core.IAM
import IRSAM.Interpreters.Shell

namespace IRSAM.Binders.Subprocess

open IRSAM.Core IRSAM.Shell

/-- Declared parameterizing-API set for ``binders/python_subprocess.yaml``. -/
def pythonSubprocessApis : List String :=
  [ "subprocess.run"
  , "subprocess.call"
  , "subprocess.check_call"
  , "subprocess.check_output"
  , "subprocess.Popen" ]

/-- Declared parameterizing-API set for ``binders/java_processbuilder.yaml``. -/
def javaProcessBuilderApis : List String :=
  [ "java.lang.ProcessBuilder.<init>"
  , "java.lang.ProcessBuilder.start"
  , "java.lang.Runtime.exec" ]

/-- Declared parameterizing-API set for ``binders/jsts_child_process.yaml``. -/
def jstsChildProcessApis : List String :=
  [ "child_process.execFile"
  , "child_process.execFileSync"
  , "child_process.spawn"
  , "child_process.spawnSync" ]

/-- A successful argv binder run: the safe call is one of the
declared APIs and the result is an argv vector. -/
structure SafeCall where
  api  : String
  argv : Argv
  deriving Repr

end IRSAM.Binders.Subprocess
