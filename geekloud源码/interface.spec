# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(
    ['interface.py',
    'builder.py',
    'database.py',
    'setup_env.py',
    'utils.py',
    'geekloud2cydx.py',
    'geekloud2spdx.py',
    'cydx2geekloud.py',
    'spdx2geekloud.py',
    'geek_transfer.py',
    'analysis_tools.py',
    ],
    pathex=['.'],
    binaries=[('SBOM','SBOM')],
    datas=[],
    hiddenimports=['builder','database','setup_env','geekloud2cydx','geekloud2spdx','cydx2geekloud','spdx2geekloud','geek_transfer'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='geekloud',
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
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='geekloud',
)
