import os
import requests
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import msal
import uvicorn

# --- CONFIGURATION ---
# In a real app, load these from environment variables
TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]

app = FastAPI(title="Azure AD Hierarchy API")

# Enable CORS for the React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MSAL SERVICE ---
class GraphService:
    def __init__(self):
        self.app = msal.ConfidentialClientApplication(
            CLIENT_ID,
            authority=AUTHORITY,
            client_credential=CLIENT_SECRET,
        )

    def _get_headers(self):
        result = self.app.acquire_token_for_client(scopes=SCOPE)
        if "access_token" in result:
            return {"Authorization": "Bearer " + result["access_token"]}
        else:
            print(f"Error acquiring token: {result.get('error')}")
            print(f"Description: {result.get('error_description')}")
            raise HTTPException(status_code=500, detail="Could not acquire Graph API token")

    def search_groups(self, query: str) -> List[Dict]:
        headers = self._get_headers()
        # Search for groups starting with the query string
        url = f"{GRAPH_ENDPOINT}/groups?$filter=startswith(displayName, '{query}')&$select=id,displayName,description,groupTypes"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('value', [])
        return []

    def get_group_details(self, group_id: str) -> Dict:
        headers = self._get_headers()
        url = f"{GRAPH_ENDPOINT}/groups/{group_id}?$select=id,displayName,description"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        raise HTTPException(status_code=404, detail="Group not found")

    def get_members(self, group_id: str) -> List[Dict]:
        headers = self._get_headers()
        # Get direct members (users and groups)
        # Note: @odata.type cannot be in $select, it's automatically included
        url = f"{GRAPH_ENDPOINT}/groups/{group_id}/members?$select=id,displayName,userPrincipalName,givenName,surname"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            members = response.json().get('value', [])
            print(f"  🔍 API returned {len(members)} members from Graph API")
            return members
        else:
            print(f"  ❌ Failed to get members: {response.status_code} - {response.text[:200]}")
        return []

    def get_owners(self, group_id: str) -> List[Dict]:
        headers = self._get_headers()
        url = f"{GRAPH_ENDPOINT}/groups/{group_id}/owners?$select=id,displayName,userPrincipalName"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('value', [])
        return []

    def get_parents(self, group_id: str) -> List[Dict]:
        headers = self._get_headers()
        # Get groups this group is a member of (parents)
        url = f"{GRAPH_ENDPOINT}/groups/{group_id}/memberOf?$select=id,displayName"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('value', [])
        return []

graph_service = GraphService()

# --- DATA MODELS ---
class GroupSearchResponse(BaseModel):
    id: str
    displayName: str
    description: Optional[str] = None

class HierarchyNode(BaseModel):
    id: str
    type: str # 'group' or 'user'
    displayName: str
    parentId: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class HierarchyResponse(BaseModel):
    nodes: List[HierarchyNode]
    edges: List[Dict[str, str]] # {"source": id, "target": id}

# --- ENDPOINTS ---

@app.get("/api/groups/search", response_model=List[GroupSearchResponse])
def search_groups(q: str = Query(..., min_length=2)):
    """Search for Azure AD groups by display name."""
    results = graph_service.search_groups(q)
    return [
        GroupSearchResponse(
            id=g['id'], 
            displayName=g.get('displayName', 'Unnamed'), 
            description=g.get('description')
        ) for g in results
    ]

@app.get("/api/groups/hierarchy/{group_id}")
def get_group_hierarchy(group_id: str):
    """
    Fetches the immediate neighborhood of a group:
    1. The group itself
    2. Its direct members (Child Groups & Users)
    3. Its direct parents (Groups it belongs to)
    """
    
    # 1. Fetch Central Group
    try:
        root = graph_service.get_group_details(group_id)
    except:
        raise HTTPException(status_code=404, detail="Group not found")

    nodes = []
    edges = []
    
    # Add Root Node
    nodes.append({
        "id": root['id'],
        "type": "root",
        "displayName": root.get('displayName'),
        "data": root
    })

    # 2. Fetch Members (Children)
    members = graph_service.get_members(group_id)
    print(f"📊 Group '{root.get('displayName')}' has {len(members)} members")
    for m in members:
        # Determine type
        odata_type = m.get('@odata.type', '')
        node_type = 'group' if 'microsoft.graph.group' in odata_type.lower() else 'user'
        print(f"  ✓ Member: {m.get('displayName')} (type: {node_type})")
        
        nodes.append({
            "id": m['id'],
            "type": node_type,
            "displayName": m.get('displayName'),
            "data": m
        })
        # Edge: Root -> Member
        edges.append({"source": root['id'], "target": m['id'], "type": "contains"})

    # 3. Fetch Parents (MemberOf)
    parents = graph_service.get_parents(group_id)
    print(f"📊 Group '{root.get('displayName')}' has {len(parents)} parents")
    for p in parents:
        print(f"  ✓ Parent: {p.get('displayName')}")
        nodes.append({
            "id": p['id'],
            "type": "group",
            "displayName": p.get('displayName'),
            "data": p
        })
        # Edge: Parent -> Root
        edges.append({"source": p['id'], "target": root['id'], "type": "contains"})

    return {
        "nodes": nodes,
        "edges": edges
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
