import json, urllib.request, datetime, sys
try:
    import yaml
    with open('modules.yaml') as f:
        requested = yaml.safe_load(f)['requested_modules']
except ImportError:
    # Fallback: simple line parser if pyyaml not available
    with open('modules.yaml') as f:
        requested = [
            line.strip().lstrip('- ')
            for line in f
            if line.strip().startswith('- ')
        ]

url = 'https://forgeapi.puppet.com/v3/modules?endorsements=validated&limit=100&fields=slug,downloads,current_release'
with urllib.request.urlopen(url) as r:
    forge_modules = json.load(r)['results']

details = {m['slug']: m for m in forge_modules}
validated = set(details.keys())

covered = sorted([m for m in requested if m in validated])
missing = sorted([m for m in requested if m not in validated])

today = datetime.date.today().isoformat()

lines = [
    f'# Puppet Forge Validated Module Coverage',
    f'',
    f'_Last updated: {today}_',
    f'',
    f'**{len(covered)}/{len(requested)} requested modules have Validated status.**',
    f'',
    f'## Covered',
    f'',
    f'| Module | Version | Downloads |',
    f'|--------|---------|-----------|',
]

for mod in covered:
    d = details[mod]
    version = d['current_release']['version'] if d.get('current_release') else 'N/A'
    downloads = f"{d.get('downloads', 0):,}"
    lines.append(f'| {mod} | {version} | {downloads} |')

lines += [
    f'',
    f'## Not Yet Validated',
    f'',
    f'| Module |',
    f'|--------|',
]
for mod in missing:
    lines.append(f'| {mod} |')

with open('README.md', 'w') as f:
    f.write('\n'.join(lines) + '\n')

print(f"Report written to README.md: {len(covered)}/{len(requested)} covered")
