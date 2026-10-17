#!/usr/bin/env python3
"""Static read-only audit of the pinned sparse HTML5 reference. No JS executed.

Checks Git objects actually present, source anchors and previous ROM evidence.
It proves source provenance and comparisons, not HTML5 raster equivalence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / 'external/goldensun_html5'
COMMIT = 'b8b086dc4a15025778acd1ce861c4ef7d6fda426'
ALLOWED_ROOT = {'.gitattributes','.gitignore','LICENSE.txt','README.md','package.json','tsconfig.json'}

def sha(data): return hashlib.sha256(data).hexdigest()

def git(*args):
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git',*args],cwd=REPO,env=env,stderr=subprocess.PIPE).decode()

def allowed(path):
    return (path in ALLOWED_ROOT or path.startswith(('base/','types/'))
            or (path.startswith('assets/filters/') and path.endswith('.js')))

def anchor(path, needles):
    data = (REPO/path).read_text()
    lines = data.splitlines()
    result = []
    for needle in needles:
        matches = [i+1 for i,line in enumerate(lines) if needle in line]
        assert matches, (path,needle)
        result.append({'needle':needle,'lines':matches})
    return {'path':path,'sha256':sha((REPO/path).read_bytes()),'anchors':result}

def main():
    assert git('rev-parse','HEAD').strip() == COMMIT
    assert git('remote','get-url','origin').strip() == 'https://github.com/jjppof/goldensun_html5.git'
    assert git('rev-parse','--is-shallow-repository').strip() == 'true'
    assert git('config','--get','remote.origin.partialclonefilter').strip() == 'blob:none'
    assert git('status','--porcelain=v1') == ''
    tree = []
    for line in git('ls-tree','-r','HEAD').splitlines():
        info,path = line.split('\t',1)
        mode,kind,oid = info.split()
        tree.append({'path':path,'kind':kind,'oid':oid,'mode':mode})
    # --batch-all-objects only enumerates local objects; never lazy-fetch a blob.
    present = {line.split()[0]:line.split()[1] for line in
               git('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)').splitlines()}
    fetched = [t for t in tree if t['kind']=='blob' and t['oid'] in present]
    forbidden = [t['path'] for t in fetched if not allowed(t['path'])]
    assert forbidden == [], forbidden
    assert not any(t['kind']=='commit' for t in tree)  # no submodule gitlinks
    assert not (REPO/'node_modules').exists() and not (REPO/'dist').exists()
    tracked = sorted(t['path'] for t in fetched)
    files = sorted(str(p.relative_to(REPO)) for p in REPO.rglob('*')
                   if p.is_file() and '.git' not in p.relative_to(REPO).parts)
    assert files == tracked
    for t in fetched:
        data = (REPO/t['path']).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==t['oid']
    rules = [t['path'] for t in tree if re.search(r'(^|/)(AGENTS\.md|CLAUDE\.md|CONTRIBUTING[^/]*)$',t['path'],re.I)]
    assert not rules
    anchors = [
        anchor('README.md',['PhaserJS CE 2.19.0','does not aim to do exactly the same engine','Javascript (legacy) and Typescript','their media are property']),
        anchor('LICENSE.txt',['MIT License','Copyright (c) 2020 Joao Paulo Oliveira Fernandes','permission notice shall be included']),
        anchor('base/GoldenSun.ts',['renderer: Phaser.WEBGL','antialias: false','roundPixels = true','private async create()','private update()']),
        anchor('base/SpriteBase.ts',['game.load.atlasJSONHash','Phaser.Animation.generateFrameNames','sprite.animations.add','frame_counts[i] - 1','frame_rate,']),
        anchor('base/initializers/npcs.ts',['action_obj.frames_count','action_obj.frame_rate','action_obj.spritesheet.image','generateAllFrames()']),
        anchor('base/utils.ts',['export enum directions','right = 0','down_right = 1','left = 4','up_right = 7','export const directions_angles']),
        anchor('base/ControllableChar.ts',['this.sprite.anchor.setTo(anchor_x, anchor_y)','this.sprite.roundPx = true','reverse_directions[this.current_direction]']),
        anchor('base/battle/PlayerSprite.ts',['this._char_sprite.anchor.setTo(0.5, 1)','this._char_sprite.available_filters[tint_filter.key]']),
        anchor('base/battle/BattleStage.ts',['Math.cos(relative_angle) <= 0','player_sprite.scale.setTo(-player_sprite.scale.x, player_sprite.scale.y)']),
        anchor('assets/filters/tint.js',['uniform sampler2D','texture2D','gl_FragColor.r']),
        anchor('assets/filters/pixel_shift.js',['uniform float      x_shift','uv = (uv_px + shift) / resolution']),
        anchor('base/battle/BattleAnimation.ts',['$08680000','0x80 (128, 8-bit graphics)','0x20 (32,']),
    ]
    utils=(REPO/'base/utils.ts').read_text()
    enum=re.search(r'export enum directions\s*\{([^}]+)\}',utils).group(1)
    directions={key:int(value) for key,value in re.findall(r'(\w+)\s*=\s*(\d+)',enum)}
    assert list(directions.values())==list(range(8))
    numbers=(REPO/'base/magic_numbers.ts').read_text()
    dimensions={key:int(re.search(r'export const '+key+r' = (\d+);',numbers).group(1))
                for key in ('GAME_WIDTH','GAME_HEIGHT','TARGET_FPS')}
    assert dimensions=={'GAME_WIDTH':240,'GAME_HEIGHT':160,'TARGET_FPS':60}
    refs=json.loads((ROOT/'work/external_references.json').read_text())
    record=next(r for r in refs['repositories'] if r['name']=='goldensun_html5')
    assert record['commit']==COMMIT
    patterns=(REPO/'.git/info/sparse-checkout').read_text().splitlines()
    assert patterns==record['sparse_paths']
    prior={step:json.loads((ROOT/f'work/{filename}').read_text()) for step,filename in (
        (28,'step28_decode_verification.json'),(29,'step29_upload_verification.json'),
        (30,'step30_rgb_verification.json'),(31,'step31_ppu_verification.json'))}
    assert all(c['tile_count']==16 and c['palette_entries']==224 for c in prior[30]['cases'])
    mirror=next(c for c in prior[31]['cases'] if c['heading']=='0x8000')
    assert mirror['matrix_q8']==[-256,0,0,256] and mirror['ordinary_flip_pixel_mismatches']==246
    assert all(c['all_1024_pixel_mismatches']==0 for c in prior[31]['cases'])
    manifest={path:sha((REPO/path).read_bytes()) for path in files}
    report={
        'step':32,'method':'Static source and Git-object audit; no JS/Phaser/ROM execution',
        'repository':{'origin':record['origin'],'commit':COMMIT,'branch':git('branch','--show-current').strip(),
            'shallow':True,'filter':'blob:none','sparse_paths':patterns,'clean':True,
            'tracked_tree_entries':len(tree),'present_tracked_blobs':len(fetched),
            'missing_tracked_blobs':sum(t['kind']=='blob' and t['oid'] not in present for t in tree),
            'forbidden_present_blobs':forbidden,'rule_files':rules},
        'source_manifest_sha256':manifest,'source_anchors':anchors,
        'parsed_html5_constants':{'directions':directions,**dimensions},
        'comparison':{
            'concordant_concepts':['240x160 viewport','Named directional sprite animations','Horizontal mirror transform exists in battle'],
            'different_representations':['HTML5 image+JSON atlas vs 16 native 8x8 8bpp OBJ tiles',
                'Texture RGB shader operations vs shared 224-entry OBJ BGR555 palette',
                'Phaser scale.x sign and anchor vs native inverse-sampled Q8 OAM matrix',
                'Eight named field directions vs native 16-bit heading and per-sprite direction selection',
                'Atlas generated frame names/rates vs ROM animation script and frame IDs'],
            'unknown':['Identity of HTML5 assets with SPR_000 pixels, palette and animation timings',
                'Raster pixel centre and 32-x versus 31-x behavior in Phaser',
                'Exact mapping of named directions and atlas IDs to ROM metadata/heading'],
            'rom_reference':{'tile_count':16,'obj_palette_entries':224,'mirrored_heading':'0x8000',
                'mirror_matrix_q8':mirror['matrix_q8'],'simple_flip_mismatches':246,
                'ppu_pixel_mismatches':0,'authority':'Existing ROM/Unicorn and mGBA proofs, not HTML5'},
            'html5_pixel_equivalence_claimed':False},
        'dependencies_installed':False,'build_run':False,'submodule_init_run':False,
        'game_assets_downloaded':False,'shader_sources_in_assets_filters_are_code':True,
        'ghidra_started':False,'ghidra_mutated':False,
        'provenance_sha256':{p:sha((ROOT/p).read_bytes()) for p in (
            'scripts/audit_html5_reference.py','work/external_references.json','external/README.md',
            'work/step28_decode_verification.json','work/step29_upload_verification.json',
            'work/step30_rgb_verification.json','work/step31_ppu_verification.json')},
        'limits':['No execution of the HTML5 engine or its renderer',
                  'No media/atlas/database blobs fetched; source-only sparse selection',
                  'Live wiki guidelines consulted separately, not pinned by code commit',
                  'Source anchors are textual checks, not a proof of runtime equivalence']}
    Path(sys.argv[1]).write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'step':32,'present_source_blobs':len(fetched),'forbidden_blobs':0,
                      'directions':len(directions),'pixel_equivalence_claimed':False}))

if __name__=='__main__':main()
