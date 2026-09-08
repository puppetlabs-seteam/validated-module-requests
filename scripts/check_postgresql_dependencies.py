import json, urllib.request, sys

try:
    import yaml
    with open('modules.yaml') as f:
        requested = yaml.safe_load(f)['requested_modules']
except ImportError:
    with open('modules.yaml') as f:
        requested = [
            line.strip().removeprefix('- ')
            for line in f
            if line.strip().startswith('- ')
        ]

POSTGRESQL_SLUGS = {'puppetlabs-postgresql', 'puppet-postgresql'}

print("Checking modules for postgresql dependencies...\n")

modules_with_pg = []
errors = []

for module_slug in sorted(requested):
    parts = module_slug.split('-', 1)
    if len(parts) != 2:
        errors.append(f"  Skipping invalid slug: {module_slug}")
        continue
    author, name = parts
    url = f'https://forgeapi.puppet.com/v3/modules/{author}-{name}?fields=current_release'
    try:
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
    except Exception as e:
        errors.append(f"  ⚠️  Could not fetch {module_slug}: {e}")
        continue

    release = data.get('current_release')
    if not release:
        continue

    metadata = release.get('metadata', {})
    dependencies = metadata.get('dependencies', [])

    pg_deps = [
        d for d in dependencies
        if d.get('name', '').lower().replace('/', '-') in POSTGRESQL_SLUGS
    ]

    if pg_deps:
        version_req = pg_deps[0].get('version_requirement', 'any')
        modules_with_pg.append({
            'module': module_slug,
            'version': release.get('version', 'N/A'),
            'pg_version_requirement': version_req,
        })

if errors:
    print("Warnings:")
    for e in errors:
        print(e)
    print()

if modules_with_pg:
    print(f"Found {len(modules_with_pg)} module(s) with postgresql dependencies:\n")
    print(f"{'Module':<40} {'Version':<12} {'PostgreSQL Requirement'}")
    print(f"{'-'*40} {'-'*12} {'-'*30}")
    for entry in modules_with_pg:
        print(f"{entry['module']:<40} {entry['version']:<12} {entry['pg_version_requirement']}")
    print("\n⚠️  These modules may need updates for PostgreSQL 17 compatibility.")
    sys.exit(1)
else:
    print("✅ No modules have direct postgresql dependencies.")
    sys.exit(0)
