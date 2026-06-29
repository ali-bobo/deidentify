# -*- mode: python ; coding: utf-8 -*-
import os, site
# tkinterdnd2 native DLL 需要一起打包
_dnd_pkg = None
for sp in site.getsitepackages():
    candidate = os.path.join(sp, 'tkinterdnd2')
    if os.path.isdir(candidate):
        _dnd_pkg = candidate
        break
_dnd_datas = [(os.path.join(_dnd_pkg, 'tkdnd'), 'tkinterdnd2/tkdnd')] if _dnd_pkg else []

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[('rules.yaml', '.')] + _dnd_datas,
    hiddenimports=['tkinterdnd2'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # PyInstaller 靜態分析掃到但 runtime 完全不用的套件
        'pandas', 'pyarrow',
        'PIL', 'Pillow',
        'grpc', 'grpcio',
        'lxml',
        'IPython',
        'matplotlib',
        'sklearn', 'scikit_learn',
        'torch', 'tensorflow',
        'sqlalchemy',
        'boto3', 'botocore',
        'docx', 'openpyxl', 'xlrd', 'xlwt',
        'pytest', 'mypy', 'black', 'isort',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='deidentify-tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='deidentify-tool',
)
