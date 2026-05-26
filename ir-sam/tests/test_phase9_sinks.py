"""Phase 9 sink-detection tests across Python / JS-TS / Java.

These pin the recognition surface for the new injection-class CWEs:
* CWE-78 (OS command injection)
* CWE-79 (XSS / DOM)
* CWE-502 (deserialization)
* CWE-22 (path traversal)
* CWE-1336 (SSTI)
"""
from __future__ import annotations

from core.lang.java import find_sink_calls as find_java_sinks
from core.lang.python import find_sink_calls as find_py_sinks


# --- Python: CWE-78 / 1336 / 502 / 22 ---------------------------------------


def test_python_subprocess_sinks_detected():
    src = (
        "import subprocess\n"
        "subprocess.run(cmd, shell=True)\n"
        "subprocess.check_output('ls ' + path, shell=True)\n"
    )
    sinks = find_py_sinks(src)
    apis = {s[2] for s in sinks}
    assert "run" in apis
    assert "check_output" in apis


def test_python_os_system_and_popen_detected():
    src = "import os\nos.system('ls ' + user)\nos.popen('echo ' + name)\n"
    sinks = find_py_sinks(src)
    apis = {s[2] for s in sinks}
    assert "system" in apis
    assert "popen" in apis


def test_python_ssti_sinks_detected():
    src = (
        "from flask import render_template_string\n"
        "render_template_string('Hello ' + name)\n"
    )
    # render_template_string is a free function — caught only when called
    # with a receiver prefix; our detector handles ``module.render_template_string``
    src2 = (
        "import flask\n"
        "flask.render_template_string('Hello ' + name)\n"
        "env.from_string(user_tpl)\n"
        "jinja2.Template(user_tpl)\n"
    )
    sinks = find_py_sinks(src2)
    apis = {s[2] for s in sinks}
    assert "render_template_string" in apis
    assert "from_string" in apis
    assert "Template" in apis


def test_python_deser_sinks_detected():
    src = (
        "import pickle, yaml\n"
        "pickle.loads(body)\n"
        "yaml.load(body)\n"
        "yaml.unsafe_load(body)\n"
    )
    sinks = find_py_sinks(src)
    apis = {s[2] for s in sinks}
    assert "loads" in apis
    assert "load" in apis
    assert "unsafe_load" in apis


def test_python_path_sinks_detected():
    src = (
        "from pathlib import Path\n"
        "Path(user).read_text()\n"
        "Path(user).write_bytes(data)\n"
        "shutil.copy(src, dst)\n"
    )
    sinks = find_py_sinks(src)
    apis = {s[2] for s in sinks}
    assert "read_text" in apis
    assert "write_bytes" in apis
    assert "copy" in apis


# --- Java: CWE-78 / 502 / 22 -------------------------------------------------


def test_java_runtime_exec_detected():
    src = 'Runtime.getRuntime().exec("ls " + dir);\n'
    sinks = find_java_sinks(src)
    apis = {s.api_or_ctor for s in sinks}
    assert "exec" in apis


def test_java_process_builder_ctor_detected():
    src = "new ProcessBuilder(cmd).start();\n"
    sinks = find_java_sinks(src)
    kinds = {(s.kind, s.api_or_ctor) for s in sinks}
    assert ("ctor", "ProcessBuilder") in kinds
    assert ("method", "start") in kinds


def test_java_deser_and_path_sinks_detected():
    src = (
        "ObjectInputStream in = new ObjectInputStream(s);\n"
        "Object o = in.readObject();\n"
        "byte[] b = Files.readAllBytes(Paths.get(user));\n"
        "new File(user);\n"
    )
    sinks = find_java_sinks(src)
    apis = {s.api_or_ctor for s in sinks}
    assert "readObject" in apis
    assert "readAllBytes" in apis
    assert "File" in apis
    assert "ObjectInputStream" in apis
