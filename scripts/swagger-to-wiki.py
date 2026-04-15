#!/usr/bin/env python3
"""Convert swagger.json to a Markdown wiki page."""
import json
import sys

def resolve_ref(ref):
    """Convert #/definitions/pkg.TypeName to TypeName."""
    if ref and ref.startswith("#/definitions/"):
        name = ref.split("/")[-1]
        # Remove package prefix (e.g., "client.CreateInput" -> "CreateInput")
        if "." in name:
            name = name.split(".", 1)[1]
        return f"`{name}`"
    return ref

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <swagger.json> <output.md>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        spec = json.load(f)

    lines = []
    info = spec.get("info", {})
    lines.append(f"# {info.get('title', 'API Documentation')}")
    lines.append("")
    if info.get("description"):
        lines.append(info["description"])
        lines.append("")
    lines.append(f"**Version:** {info.get('version', '')}  ")
    lines.append(f"**Host:** {spec.get('host', '')}  ")
    lines.append(f"**Base Path:** {spec.get('basePath', '/')}")
    lines.append("")

    # Group by tags
    tag_ops = {}
    for path, methods in sorted(spec.get("paths", {}).items()):
        for method, op in methods.items():
            if method in ("parameters",):
                continue
            tags = op.get("tags", ["Untagged"])
            for tag in tags:
                tag_ops.setdefault(tag, []).append((method.upper(), path, op))

    # Table of contents
    lines.append("## Table of Contents")
    lines.append("")
    for tag in sorted(tag_ops.keys()):
        anchor = tag.lower().replace(" ", "-").replace(".", "")
        count = len(tag_ops[tag])
        lines.append(f"- [{tag}](#{anchor}) ({count} endpoints)")
    definitions = spec.get("definitions", {})
    if definitions:
        lines.append(f"- [Models](#models) ({len(definitions)} schemas)")
    lines.append("")

    for tag in sorted(tag_ops.keys()):
        lines.append(f"## {tag}")
        lines.append("")
        for method, path, op in tag_ops[tag]:
            summary = op.get("summary", "")
            lines.append(f"### `{method}` {path}")
            lines.append("")
            if summary:
                lines.append(summary)
                lines.append("")

            # Parameters
            params = op.get("parameters", [])
            if params:
                lines.append("**Parameters:**")
                lines.append("")
                lines.append("| Name | In | Type | Required | Description |")
                lines.append("|------|-----|------|----------|-------------|")
                for p in params:
                    name = p.get("name", "")
                    loc = p.get("in", "")
                    required = "Yes" if p.get("required") else "No"
                    desc = p.get("description", "")
                    if "schema" in p:
                        ptype = p["schema"].get("type", resolve_ref(p["schema"].get("$ref", "object")))
                    else:
                        ptype = p.get("type", "string")
                    lines.append(f"| {name} | {loc} | {ptype} | {required} | {desc} |")
                lines.append("")

            # Responses
            responses = op.get("responses", {})
            if responses:
                lines.append("**Responses:**")
                lines.append("")
                lines.append("| Code | Description |")
                lines.append("|------|-------------|")
                for code, resp in sorted(responses.items()):
                    desc = resp.get("description", "")
                    lines.append(f"| {code} | {desc} |")
                lines.append("")

            # Security
            security = op.get("security", [])
            if security:
                schemes = [list(s.keys())[0] for s in security if s]
                if schemes:
                    lines.append(f"**Auth:** {', '.join(schemes)}")
                    lines.append("")

            lines.append("---")
            lines.append("")

    # Models / Definitions
    definitions = spec.get("definitions", {})
    if definitions:
        lines.append("## Models")
        lines.append("")
        for name, schema in sorted(definitions.items()):
            short_name = name.split(".", 1)[1] if "." in name else name
            pkg = name.split(".", 1)[0] if "." in name else ""
            lines.append(f"### `{short_name}`")
            if pkg:
                lines.append(f"*Package: {pkg}*")
                lines.append("")
            props = schema.get("properties", {})
            required = schema.get("required", [])
            if props:
                lines.append("| Field | Type | Required | Description |")
                lines.append("|-------|------|----------|-------------|")
                for field, info in sorted(props.items()):
                    ftype = info.get("type", "")
                    if not ftype and "$ref" in info:
                        ftype = resolve_ref(info["$ref"])
                    if ftype == "array" and "items" in info:
                        item_type = info["items"].get("type", "")
                        if not item_type and "$ref" in info["items"]:
                            item_type = resolve_ref(info["items"]["$ref"])
                        ftype = f"{item_type}[]"
                    req = "Yes" if field in required else "No"
                    desc = info.get("description", "")
                    lines.append(f"| {field} | {ftype} | {req} | {desc} |")
            else:
                lines.append("*No properties defined.*")
            lines.append("")

    with open(sys.argv[2], "w") as f:
        f.write("\n".join(lines))

    model_count = len(definitions)
    print(f"Generated {sys.argv[2]} ({len(tag_ops)} tags, {sum(len(v) for v in tag_ops.values())} endpoints, {model_count} models)")

if __name__ == "__main__":
    main()
