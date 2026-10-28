"""Bind this project to its existing venv in JetBrains IDEs (run with IDEs closed)."""
import argparse
import csv
from datetime import datetime
import io
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / '.venv/Scripts/python.exe'
SDK_NAME = 'tabbyShop (.venv)'
CONFIG_ROOT = Path.home() / 'AppData/Roaming/JetBrains'


def targets():
    return sorted(p for p in CONFIG_ROOT.iterdir()
                  if p.is_dir() and p.name.startswith(('IntelliJIdea', 'PyCharm')))


def running_ides():
    names = set()
    for name in ('idea64.exe', 'pycharm64.exe'):
        result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                                capture_output=True, text=True, errors='replace', check=True,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for row in csv.reader(io.StringIO(result.stdout)):
            if row and row[0].lower() == name:
                names.add(name)
    return sorted(names)


def xml_bytes(tree):
    ET.indent(tree, space='  ')
    return ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True) + b'\n'


def build_changes(config_dirs):
    changes = {}
    for config in config_dirs:
        path = config / 'options/jdk.table.xml'
        tree = ET.parse(path) if path.exists() else ET.ElementTree(ET.Element('application'))
        component = tree.getroot().find("component[@name='ProjectJdkTable']")
        if component is None:
            component = ET.SubElement(tree.getroot(), 'component', name='ProjectJdkTable')
        for old in list(component.findall('jdk')):
            name = old.find('name')
            if name is not None and name.get('value') == SDK_NAME:
                component.remove(old)
        sdk = ET.SubElement(component, 'jdk', version='2')
        for tag, value in (('name', SDK_NAME), ('type', 'Python SDK'),
                           ('version', 'Python ' + sys.version.split()[0]), ('homePath', PYTHON.as_posix())):
            ET.SubElement(sdk, tag, value=value)
        roots = ET.SubElement(sdk, 'roots')
        for kind in ('classPath', 'sourcePath'):
            entries = ET.SubElement(ET.SubElement(roots, kind), 'root', type='composite')
            if kind == 'classPath':
                for directory in (Path(sys.base_prefix) / 'Lib', Path(sys.base_prefix) / 'DLLs',
                                  Path(sysconfig.get_path('purelib'))):
                    if directory.exists():
                        ET.SubElement(entries, 'root', url='file://' + directory.as_posix(), type='simple')
        ET.SubElement(sdk, 'additional', ASSOCIATED_PROJECT_PATH=str(ROOT))
        changes[path] = xml_bytes(tree)

    misc = ROOT / '.idea/misc.xml'
    tree = ET.parse(misc) if misc.exists() else ET.ElementTree(ET.Element('project', version='4'))
    manager = tree.getroot().find("component[@name='ProjectRootManager']")
    if manager is None:
        manager = ET.SubElement(tree.getroot(), 'component', name='ProjectRootManager', version='2')
    manager.set('project-jdk-name', SDK_NAME)
    manager.set('project-jdk-type', 'Python SDK')
    changes[misc] = xml_bytes(tree)

    module_path = ROOT / '.idea/tabbyShop.iml'
    tree = ET.parse(module_path) if module_path.exists() else ET.ElementTree(ET.Element('module', version='4'))
    tree.getroot().set('type', 'PYTHON_MODULE')
    manager = tree.getroot().find("component[@name='NewModuleRootManager']")
    if manager is None:
        manager = ET.SubElement(tree.getroot(), 'component', name='NewModuleRootManager', **{'inherit-compiler-output': 'true'})
    content = manager.find('content')
    if content is None:
        content = ET.SubElement(manager, 'content')
    content.set('url', 'file://$PROJECT_DIR$')
    for excluded in content.findall('excludeFolder'):
        if excluded.get('url') == 'file://$MODULE_DIR$/.venv':
            excluded.set('url', 'file://$PROJECT_DIR$/.venv')
    for directory in ('.venv', 'exports'):
        url = 'file://$PROJECT_DIR$/' + directory
        if not any(e.get('url') == url for e in content.findall('excludeFolder')):
            ET.SubElement(content, 'excludeFolder', url=url)
    for entry in list(manager.findall('orderEntry')):
        if entry.get('type') in ('jdk', 'inheritedJdk'):
            manager.remove(entry)
    ET.SubElement(manager, 'orderEntry', type='inheritedJdk')
    changes[module_path] = xml_bytes(tree)

    tree = ET.ElementTree(ET.Element('component', name='ProjectRunConfigurationManager'))
    run = ET.SubElement(tree.getroot(), 'configuration', default='false', name='TabbyDesktop',
                        type='PythonConfigurationType', factoryName='Python')
    ET.SubElement(run, 'module', name='tabbyShop')
    for name, value in (('SDK_HOME', PYTHON.as_posix()), ('IS_MODULE_SDK', 'false'),
                        ('WORKING_DIRECTORY', '$PROJECT_DIR$'), ('SCRIPT_NAME', '$PROJECT_DIR$/desktop.py'),
                        ('ADD_CONTENT_ROOTS', 'true'), ('ADD_SOURCE_ROOTS', 'true'), ('PARENT_ENVS', 'true')):
        ET.SubElement(run, 'option', name=name, value=value)
    ET.SubElement(ET.SubElement(run, 'envs'), 'env', name='PYTHONUNBUFFERED', value='1')
    ET.SubElement(run, 'method', v='2')
    changes[ROOT / '.idea/runConfigurations/TabbyDesktop.xml'] = xml_bytes(tree)
    workspace = ROOT / '.idea/workspace.xml'
    if workspace.exists():
        original = workspace.read_text(encoding='utf-8')
        updated = re.sub(r'(<component name="RunManager"[^>]* selected=")[^"]*',
                         r'\g<1>Python.TabbyDesktop', original, count=1)
        if updated != original:
            changes[workspace] = updated.encode('utf-8')
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Validate generated config without changing files')
    args = parser.parse_args()
    if not PYTHON.exists() or Path(sys.executable).resolve() != PYTHON.resolve():
        print(r'Run: .\.venv\Scripts\python.exe .\tools\configure_ide.py')
        return 1
    config_dirs = targets()
    if not config_dirs:
        print('No JetBrains configuration directory found.')
        return 1
    changes = build_changes(config_dirs)
    for path, data in changes.items():
        ET.fromstring(data)
        print(('CHECK ' if args.check else 'CONFIG ') + str(path))
    if args.check:
        print('Validation passed. Interpreter: ' + str(PYTHON))
        return 0
    running = running_ides()
    if running:
        print('Close IntelliJ IDEA and PyCharm first, then run this command in Windows PowerShell.')
        print('Still running: ' + ', '.join(running))
        print('No files changed.')
        return 1
    backup = ROOT / 'exports/ide-config-backup' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup.mkdir(parents=True)
    for index, path in enumerate(changes):
        if path.exists():
            shutil.copy2(path, backup / f'{index}-{path.name}')
    (backup / 'paths.txt').write_text('\n'.join(f'{i}-{p.name}: {p}' for i, p in enumerate(changes)), encoding='utf-8')
    for path, data in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + '.tabby-config.tmp')
        temp.write_bytes(data)
        temp.replace(path)
    print('Configured: ' + SDK_NAME)
    print('Interpreter: ' + str(PYTHON))
    print('Backup: ' + str(backup))
    print('Reopen the project and run TabbyDesktop.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
