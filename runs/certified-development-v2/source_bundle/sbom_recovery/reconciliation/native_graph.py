"""Normalize native reports only; never ingest scanner graphs as gold."""
from __future__ import annotations

def normalize(ecosystem, raw, project_name):
    if ecosystem=="pypi":
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        records = {canonicalize_name(r["metadata"]["name"]):r["metadata"] for r in raw["installed"]}
        root = canonicalize_name(project_name)
        if root not in records: raise ValueError("Root missing from installed environment")
        context = raw["environment"]
        active = {root:set()}; edges=set(); changed=True
        while changed:
            changed=False
            for name,extras in list(active.items()):
                for declaration in records[name].get("requires_dist",[]):
                    req=Requirement(declaration); dest=canonicalize_name(req.name)
                    if req.marker:
                        from packaging._parser import Variable
                        def variables(tree):
                            found=set()
                            for item in tree:
                                if isinstance(item,list): found.update(variables(item))
                                elif isinstance(item,tuple): found.update(x.value for x in item if isinstance(x,Variable))
                            return found
                        if not variables(req.marker._markers) <= (set(context)|{"extra"}):
                            raise ValueError("Context-Uncertain: missing marker environment")
                    if req.marker and not any(req.marker.evaluate({**context,"extra":x}) for x in (extras|{""})): continue
                    if dest not in records or records[dest]["version"] not in req.specifier: raise ValueError("Unresolved installed requirement")
                    edges.add((name,dest))
                    if dest not in active: active[dest]=set(req.extras); changed=True
                    elif not req.extras<=active[dest]: active[dest]|=req.extras; changed=True
        return [{"id":n,"name":n,"version":records[n]["version"]} for n in sorted(active)], sorted(edges)
    if ecosystem=="npm":
        nodes={}; edges=set()
        def visit(row, name, instance):
            if row.get("missing") or row.get("invalid") or row.get("problems"): raise ValueError("npm graph has unresolved problems")
            if instance in nodes: return
            nodes[instance]={"id":instance,"name":row.get("name",name),"version":row.get("version")}
            if not nodes[instance]["version"]: raise ValueError("Missing npm version")
            for dep,child in row.get("dependencies",{}).items():
                dest=child.get("path") or instance+"/node_modules/"+dep
                dest=dest.replace("/tmp/project", "root")
                edges.add((instance,dest)); visit(child,dep,dest)
        visit(raw,project_name,"root")
        return list(nodes.values()), sorted(edges)
    if "nodes" in raw: return raw["nodes"], raw["edges"]
    nodes=[]; edges=[]
    def visit(row,instance):
        if row.get("scope","compile") not in {"compile","runtime",""}: return
        nodes.append({"id":instance,"name":row["groupId"]+":"+row["artifactId"],"version":row["version"]})
        for index,child in enumerate(row.get("children",[])):
            if child.get("scope","compile") not in {"compile","runtime",""}: continue
            dest=instance+"/"+str(index); edges.append((instance,dest)); visit(child,dest)
    visit(raw,"root")
    return nodes,edges

