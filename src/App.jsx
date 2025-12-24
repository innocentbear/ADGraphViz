import React, { useState, useEffect, useRef } from 'react';
import { 
  Search, 
  Users, 
  User, 
  ZoomIn, 
  ZoomOut, 
  RefreshCw, 
  Share2, 
  Shield, 
  Layers,
  ArrowRightCircle,
  FolderOpen,
  Download,
  Filter
} from 'lucide-react';
import './App.css';

/**
 * CONFIGURATION
 * Toggle this to FALSE to use the real Python backend.
 */
const USE_MOCK_DATA = false;
const API_BASE_URL = 'http://localhost:8000/api';

// --- MOCK DATA GENERATOR ---
const generateMockData = (rootId) => {
  const nodes = [];
  const edges = [];

  const rootName = rootId === '1' ? 'All Employees' : `Group ${rootId}`;
  
  // Central Node
  nodes.push({ id: rootId, type: 'root', displayName: rootName, description: 'Selected Target Group' });

  // Parents (Membership)
  const parentId = `p-${Date.now()}`;
  nodes.push({ id: parentId, type: 'group', displayName: 'Global Administrators' });
  edges.push({ source: parentId, target: rootId, type: 'contains' });

  // Children Groups (Members)
  for (let i = 1; i <= 3; i++) {
    const gid = `g-${rootId}-${i}`;
    nodes.push({ id: gid, type: 'group', displayName: `Engineering Team ${String.fromCharCode(64+i)}` });
    edges.push({ source: rootId, target: gid, type: 'contains' });
    
    // Users in subgroups
    for (let j = 1; j <= 2; j++) {
      const uid = `u-${gid}-${j}`;
      nodes.push({ id: uid, type: 'user', displayName: `User ${i}-${j}`, userPrincipalName: `user${i}${j}@contoso.com` });
      edges.push({ source: gid, target: uid, type: 'contains' });
    }
  }

  // Direct Users (Members)
  for (let k = 1; k <= 4; k++) {
    const uid = `du-${rootId}-${k}`;
    nodes.push({ id: uid, type: 'user', displayName: `Direct User ${k}`, userPrincipalName: `direct${k}@contoso.com` });
    edges.push({ source: rootId, target: uid, type: 'contains' });
  }

  return { nodes, edges };
};

// --- SERVICE LAYER ---

const apiService = {
  searchGroups: async (query) => {
    if (USE_MOCK_DATA) {
      await new Promise(r => setTimeout(r, 400)); // Simulate net lag
      return [
        { id: '1', type: 'group', displayName: 'All Employees', description: 'Dynamic group for all staff' },
        { id: '2', type: 'group', displayName: 'Engineering Leads', description: 'Engineering management' },
        { id: '3', type: 'group', displayName: 'Finance Dept', description: 'Access to finance apps' },
        { id: '4', type: 'group', displayName: 'Global Admins', description: 'Elevated privileges' },
      ].filter(g => g.displayName.toLowerCase().includes(query.toLowerCase()));
    }
    
    const res = await fetch(`${API_BASE_URL}/groups/search?q=${query}`);
    if (!res.ok) throw new Error('Search failed');
    return res.json();
  },

  getHierarchy: async (groupId) => {
    if (USE_MOCK_DATA) {
      await new Promise(r => setTimeout(r, 600));
      return generateMockData(groupId);
    }

    const res = await fetch(`${API_BASE_URL}/groups/hierarchy/${groupId}`);
    if (!res.ok) throw new Error('Fetch failed');
    return res.json();
  }
};

// --- COMPONENTS ---

// 1. Force Graph Component (Custom SVG Implementation)
const ForceGraph = ({ data, onNodeClick }) => {
  const svgRef = useRef(null);
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]); // simplified link objects for simulation
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Initialize Simulation Data
  useEffect(() => {
    if (!data.nodes.length) return;

    // Reset positions loosely around center with wider spread
    const width = svgRef.current?.clientWidth || 800;
    const height = svgRef.current?.clientHeight || 600;

    const initializedNodes = data.nodes.map(n => ({
      ...n,
      x: n.x || width / 2 + (Math.random() - 0.5) * 300,
      y: n.y || height / 2 + (Math.random() - 0.5) * 300,
      vx: 0,
      vy: 0
    }));

    setNodes(initializedNodes);
    setLinks(data.edges.map(e => ({ source: e.source, target: e.target })));
  }, [data]);

  // Simulation Loop
  useEffect(() => {
    if (nodes.length === 0) return;

    let animationFrameId;
    const width = svgRef.current?.clientWidth || 800;
    const height = svgRef.current?.clientHeight || 600;

    const tick = () => {
      setNodes(prevNodes => {
        // Create a shallow copy for mutation
        const nextNodes = prevNodes.map(n => ({ ...n }));
        const k = 0.03; // attraction strength (reduced for looser layout)
        const repulsion = 12000; // increased repulsion for more spacing
        const idealLinkLength = 180; // increased ideal link length
        let totalEnergy = 0; // Track movement energy
        
        // 1. Repulsion (Nodes push apart)
        for (let i = 0; i < nextNodes.length; i++) {
          for (let j = i + 1; j < nextNodes.length; j++) {
            const dx = nextNodes[i].x - nextNodes[j].x;
            const dy = nextNodes[i].y - nextNodes[j].y;
            const distSq = dx * dx + dy * dy || 1;
            const dist = Math.sqrt(distSq);
            
            // Stronger repulsion for very close nodes
            const minDist = 60;
            if (dist < minDist) {
              const f = repulsion / (minDist * minDist);
              const fx = (dx / dist) * f * 2;
              const fy = (dy / dist) * f * 2;
              
              nextNodes[i].vx += fx;
              nextNodes[i].vy += fy;
              nextNodes[j].vx -= fx;
              nextNodes[j].vy -= fy;
            } else {
              const f = repulsion / distSq;
              const fx = (dx / dist) * f;
              const fy = (dy / dist) * f;

              nextNodes[i].vx += fx;
              nextNodes[i].vy += fy;
              nextNodes[j].vx -= fx;
              nextNodes[j].vy -= fy;
            }
          }
        }

        // 2. Attraction (Edges pull together)
        links.forEach(link => {
          const source = nextNodes.find(n => n.id === link.source);
          const target = nextNodes.find(n => n.id === link.target);
          if (source && target) {
            const dx = target.x - source.x;
            const dy = target.y - source.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const force = (dist - idealLinkLength) * k;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            source.vx += fx;
            source.vy += fy;
            target.vx -= fx;
            target.vy -= fy;
          }
        });

        // 3. Center Gravity & Physics Update
        nextNodes.forEach(n => {
          n.vx += (width / 2 - n.x) * 0.005;
          n.vy += (height / 2 - n.y) * 0.005;

          // Velocity Damping (Increased Friction: 0.9 -> 0.8)
          n.vx *= 0.8; 
          n.vy *= 0.8;

          // Add to energy sum
          totalEnergy += Math.abs(n.vx) + Math.abs(n.vy);

          // Update Position
          n.x += n.vx;
          n.y += n.vy;
        });

        // Optimization: If total energy is very low, return the previous state object.
        // This prevents React from re-rendering the DOM when the graph is settled.
        if (totalEnergy < 0.2) {
          return prevNodes;
        }

        return nextNodes;
      });
      animationFrameId = requestAnimationFrame(tick);
    };

    tick();
    return () => cancelAnimationFrame(animationFrameId);
  }, [links]); 

  // Pan Handlers
  const handleWheel = (e) => {
    setTransform(t => ({
      ...t,
      k: Math.min(Math.max(0.1, t.k - e.deltaY * 0.001), 4)
    }));
  };

  const handleMouseDown = (e) => {
    // Only pan if clicking background
    if (e.target.tagName === 'svg') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    }
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      setTransform(t => ({
        ...t,
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      }));
    }
  };

  const getNodeColor = (type) => {
    if (type === 'root') return '#6366f1'; // Indigo
    if (type === 'group') return '#3b82f6'; // Blue
    return '#10b981'; // Green (User)
  };

  const getNodeIcon = (type) => {
    if (type === 'user') return <User size={16} color="white" />;
    return <Users size={16} color="white" />;
  };

  return (
    <div className="w-full h-full overflow-hidden bg-slate-50 relative border rounded-lg shadow-inner">
       <div className="absolute top-4 right-4 flex gap-2 z-10">
          <button onClick={() => setTransform(t => ({...t, k: t.k * 1.2}))} className="p-2 bg-white shadow rounded hover:bg-gray-50"><ZoomIn size={18} /></button>
          <button onClick={() => setTransform(t => ({...t, k: t.k / 1.2}))} className="p-2 bg-white shadow rounded hover:bg-gray-50"><ZoomOut size={18} /></button>
          <button onClick={() => setTransform({x:0, y:0, k:1})} className="p-2 bg-white shadow rounded hover:bg-gray-50"><RefreshCw size={18} /></button>
       </div>

       <svg 
        ref={svgRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseUp={() => setIsDragging(false)}
        onMouseLeave={() => setIsDragging(false)}
        onMouseMove={handleMouseMove}
       >
         <defs>
            {/* Green Arrow (Contains/Member) - Emerald-500 */}
            <marker id="arrow-contains" markerWidth="8" markerHeight="8" refX="26" refY="4" orient="auto" markerUnits="userSpaceOnUse">
              <path d="M0,0 L0,8 L8,4 z" fill="#10b981" />
            </marker>

            {/* Purple Arrow (Member Of/Parent) - Violet-500 */}
            <marker id="arrow-member-of" markerWidth="10" markerHeight="10" refX="28" refY="5" orient="auto" markerUnits="userSpaceOnUse">
              <path d="M0,0 L0,10 L10,5 z" fill="#8b5cf6" />
            </marker>
         </defs>

         <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
           {/* Edges */}
           {links.map((link, i) => {
             const source = nodes.find(n => n.id === link.source);
             const target = nodes.find(n => n.id === link.target);
             if (!source || !target) return null;
             
             // Backend edge structure:
             // - Members: source=root, target=child (root contains child) → GREEN arrow root→child
             // - Parents: source=parent, target=root (parent contains root) → GREEN arrow parent→root
             // 
             // To show "member of" (purple) arrows, we want: child→parent direction
             // So when source=root (root contains child), we REVERSE to show child→root as "member of"
             const isRootSource = source.type === 'root';
             const isRootTarget = target.type === 'root';
             
             // If source is root, it's a "contains" relationship, render as GREEN arrow pointing at child
             // If target is root, it's a parent relationship, render as reversed PURPLE arrow from root to parent
             let x1, y1, x2, y2, strokeColor, markerId, strokeWidth;
             
             if (isRootSource) {
               // Root → Child: Show as green "contains" arrow
               x1 = source.x; y1 = source.y;
               x2 = target.x; y2 = target.y;
               strokeColor = '#10b981'; // Green
               markerId = 'arrow-contains';
               strokeWidth = 2;
             } else if (isRootTarget) {
               // Parent → Root: Show as purple "member of" arrow FROM root TO parent
               x1 = target.x; y1 = target.y;
               x2 = source.x; y2 = source.y;
               strokeColor = '#8b5cf6'; // Purple
               markerId = 'arrow-member-of';
               strokeWidth = 2.5;
             } else {
               // Non-root edges (shouldn't happen with current backend, but default to green)
               x1 = source.x; y1 = source.y;
               x2 = target.x; y2 = target.y;
               strokeColor = '#10b981';
               markerId = 'arrow-contains';
               strokeWidth = 2;
             }

             return (
               <line 
                key={i}
                x1={x1} y1={y1}
                x2={x2} y2={y2}
                stroke={strokeColor}
                strokeWidth={strokeWidth}
                markerEnd={`url(#${markerId})`}
                opacity={0.7}
               />
             );
           })}

           {/* Nodes */}
           {nodes.map(node => (
             <g 
              key={node.id} 
              transform={`translate(${node.x},${node.y})`}
              className="cursor-pointer" 
              onClick={(e) => { e.stopPropagation(); onNodeClick(node); }}
             >
               <circle 
                r={node.type === 'root' ? 25 : 18} 
                fill={getNodeColor(node.type)} 
                className="shadow-lg transition-all duration-200 hover:brightness-110"
                stroke="white"
                strokeWidth={3}
                style={{ transformBox: 'fill-box', transformOrigin: 'center' }}
                onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.2)')}
                onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
               />
               <foreignObject x={node.type === 'root' ? -12 : -8} y={node.type === 'root' ? -12 : -8} width={24} height={24} className="pointer-events-none">
                 <div className="flex items-center justify-center w-full h-full">
                    {getNodeIcon(node.type)}
                 </div>
               </foreignObject>
               
               {/* Label */}
               <text 
                y={node.type === 'root' ? 40 : 32} 
                textAnchor="middle" 
                className="text-xs font-medium fill-slate-700 pointer-events-none select-none"
                style={{ textShadow: '0 1px 2px white' }}
               >
                 {node.displayName.length > 15 ? node.displayName.substring(0, 14) + '...' : node.displayName}
               </text>
             </g>
           ))}
         </g>
       </svg>
       
       <div className="absolute bottom-4 left-4 p-3 bg-white/90 backdrop-blur rounded-lg shadow-sm border border-slate-200 text-xs text-slate-600">
          <div className="font-bold mb-1.5 text-slate-800">Relationships</div>
          <div className="flex items-center gap-2 mb-1">
            <span className="flex items-center">
              <span className="w-4 h-0.5 bg-green-500"></span>
              <ArrowRightCircle size={12} className="text-green-500 -ml-1" />
            </span>
            <span>Contains (Parent &#8594; Child)</span>
          </div>
          <div className="flex items-center gap-2">
             <span className="flex items-center">
              <span className="w-4 h-0.5 bg-purple-500"></span>
              <ArrowRightCircle size={12} className="text-purple-500 -ml-1" />
            </span>
            <span>Member Of (Child &#8594; Parent)</span>
          </div>
       </div>
    </div>
  );
};

// --- MAIN APP ---

export default function App() {
  const [query, setQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [detailsNode, setDetailsNode] = useState(null);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState(null);
  const [memberFilter, setMemberFilter] = useState('');

  // Derived Relationship Lists for the Sidebar
  const relations = React.useMemo(() => {
    if (!detailsNode || !graphData.nodes.length) return { 
      members: [], 
      parents: [], 
      filteredMembers: [],
      userCount: 0,
      groupCount: 0
    };

    // Member: Edge Source == DetailsNode (detailsNode contains member)
    const memberEdges = graphData.edges.filter(e => e.source === detailsNode.id);
    const members = memberEdges
      .map(e => graphData.nodes.find(n => n.id === e.target))
      .filter(Boolean);

    // Parent: Edge Target == DetailsNode (parent contains detailsNode)
    const parentEdges = graphData.edges.filter(e => e.target === detailsNode.id);
    const parents = parentEdges
      .map(e => graphData.nodes.find(n => n.id === e.source))
      .filter(Boolean);

    // Filter members based on search
    const filteredMembers = memberFilter.trim() === '' 
      ? members 
      : members.filter(m => 
          m.displayName.toLowerCase().includes(memberFilter.toLowerCase()) ||
          (m.userPrincipalName && m.userPrincipalName.toLowerCase().includes(memberFilter.toLowerCase()))
        );

    // Count member types
    const userCount = members.filter(m => m.type === 'user').length;
    const groupCount = members.filter(m => m.type === 'group').length;

    console.log('👥 Computing relations for:', detailsNode.displayName);
    console.log('   Total edges:', graphData.edges.length);
    console.log('   Member edges (source=' + detailsNode.id + '):', memberEdges.length);
    console.log('   Parent edges (target=' + detailsNode.id + '):', parentEdges.length);
    console.log('   Members found:', members.map(m => m.displayName));
    console.log('   Parents found:', parents.map(p => p.displayName));

    return { members, parents, filteredMembers, userCount, groupCount };
  }, [detailsNode, graphData, memberFilter]);

  // Debounced Search
  useEffect(() => {
    const timer = setTimeout(async () => {
      if (query.length < 2) return;
      setLoading(true);
      try {
        const results = await apiService.searchGroups(query);
        setSearchResults(results);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [query]);

  // Load Hierarchy when Group Selected
  useEffect(() => {
    if (!selectedGroup) return;
    
    const loadGraph = async () => {
      setLoading(true);
      setError('');
      try {
        const data = await apiService.getHierarchy(selectedGroup.id);
        console.log('📊 Hierarchy Data Received:', data);
        console.log('📍 Nodes:', data.nodes.length);
        console.log('🔗 Edges:', data.edges.length);
        if (data.edges.length > 0) {
          console.log('Edge examples:', data.edges.slice(0, 3));
        }
        
        // Merge description from search result into root node
        const rootNode = data.nodes.find(n => n.id === selectedGroup.id);
        if (rootNode && selectedGroup.description) {
          rootNode.description = selectedGroup.description;
        }
        
        setGraphData(data);
        setDetailsNode(rootNode || null);
        console.log('🎯 Root node set to:', rootNode?.displayName);
      } catch (e) {
        console.error('❌ Failed to load hierarchy:', e);
        setError('Failed to load group hierarchy. Ensure backend is running.');
      } finally {
        setLoading(false);
      }
    };
    
    loadGraph();
  }, [selectedGroup]);

  // Copy to Clipboard Function
  const copyToClipboard = (text) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand("copy");
      setCopiedId(text);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy', err);
    }
    document.body.removeChild(textArea);
  };

  // Export to CSV Function
  const exportToCSV = () => {
    if (!detailsNode || relations.members.length === 0) return;

    const csvRows = [
      ['Display Name', 'Type', 'Object ID', 'User Principal Name'].join(','),
      ...relations.members.map(member => [
        `"${member.displayName}"`,
        member.type,
        member.id,
        member.userPrincipalName || ''
      ].join(','))
    ];

    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `${detailsNode.displayName.replace(/[^a-z0-9]/gi, '_')}_members.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="flex h-screen bg-slate-100 font-sans text-slate-800 overflow-hidden">
      
      {/* SIDEBAR */}
      <div className="w-80 bg-white border-r border-slate-200 flex flex-col shadow-xl z-20">
        
        {/* Header */}
        <div className="p-5 border-b border-slate-100 bg-slate-50">
          <div className="flex items-center gap-2 mb-1">
            <Share2 className="text-indigo-600" size={24} />
            <h1 className="text-xl font-bold text-slate-900">Azure AD Viz</h1>
          </div>
          <p className="text-xs text-slate-500">Group Hierarchy Explorer</p>
        </div>

        {/* Search Section */}
        <div className="p-4 flex-none">
          <div className="relative">
            <Search className="absolute left-3 top-3 text-slate-400" size={16} />
            <input 
              type="text" 
              className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
              placeholder="Search groups..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {loading && <div className="absolute right-3 top-3 animate-spin w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full"></div>}
          </div>

          {/* Search Results Dropdown */}
          {/* VISIBILITY FIX: Removed !selectedGroup from condition */}
          {searchResults.length > 0 && query.length >= 2 && (
            <div className="mt-2 bg-white border border-slate-200 rounded-lg shadow-lg max-h-60 overflow-y-auto absolute w-72 z-50">
              {searchResults.map(group => (
                <div 
                  key={group.id}
                  className="p-3 hover:bg-indigo-50 cursor-pointer border-b border-slate-50 last:border-0"
                  onClick={() => {
                    setSelectedGroup(group);
                    setQuery('');
                    setSearchResults([]);
                  }}
                >
                  <div className="font-medium text-sm text-slate-700">{group.displayName}</div>
                  <div className="text-xs text-slate-400 truncate">{group.description || 'No description'}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Selected Group Context */}
        {selectedGroup && (
           <div className="px-4 py-2 bg-indigo-50 border-y border-indigo-100 flex justify-between items-center">
             <div className="flex flex-col">
               <span className="text-[10px] uppercase font-bold text-indigo-400 tracking-wider">Viewing Context</span>
               <span className="text-sm font-semibold text-indigo-900 truncate w-48">{selectedGroup.displayName}</span>
             </div>
             <button onClick={() => { setSelectedGroup(null); setGraphData({nodes:[], edges:[]}); setDetailsNode(null); }} className="text-xs text-indigo-500 hover:text-indigo-700 underline">Change</button>
           </div>
        )}

        {/* Details Panel */}
        <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
          {detailsNode ? (
            <div className="space-y-4 animate-fadeIn">
              
              {/* Back to Context Button */}
              {detailsNode.id !== selectedGroup?.id && (
                <button
                  onClick={() => setDetailsNode(graphData.nodes.find(n => n.id === selectedGroup.id))}
                  className="flex items-center gap-2 text-xs text-indigo-600 hover:text-indigo-800 font-medium transition-colors mb-2"
                >
                  <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M8 2L4 6l4 4" />
                  </svg>
                  BACK TO CONTEXT
                </button>
              )}

              {/* Node Header */}
              <div className="flex items-center gap-3">
                <div className={`p-3 rounded-full ${detailsNode.type === 'user' ? 'bg-emerald-100 text-emerald-600' : 'bg-blue-100 text-blue-600'}`}>
                  {detailsNode.type === 'user' ? <User size={24} /> : <Users size={24} />}
                </div>
                <div className="flex-1">
                   <h2 className="font-bold text-lg leading-tight">{detailsNode.displayName}</h2>
                   <div className="flex items-center gap-2 mt-1">
                     <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 uppercase tracking-wide font-bold">{detailsNode.type}</span>
                     {(detailsNode.type === 'group' || detailsNode.type === 'root') && (
                       <a
                         href={`https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/${detailsNode.id}`}
                         target="_blank"
                         rel="noopener noreferrer"
                         className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:text-indigo-800 font-medium transition-colors"
                       >
                         Open in Azure
                         <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                           <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                           <polyline points="15 3 21 3 21 9"></polyline>
                           <line x1="10" y1="14" x2="21" y2="3"></line>
                         </svg>
                       </a>
                     )}
                   </div>
                </div>
              </div>

              {/* Node Metadata */}
              <div className="space-y-3 pt-4 border-t border-slate-100">
                <div>
                  <label className="text-xs font-bold text-slate-400 uppercase">Object ID</label>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="flex-1 text-xs font-mono bg-slate-100 p-2 rounded text-slate-600 break-all border border-slate-200">
                      {detailsNode.id}
                    </div>
                    <button
                      onClick={() => copyToClipboard(detailsNode.id)}
                      className="flex-shrink-0 p-2 text-slate-500 hover:text-indigo-600 hover:bg-slate-100 rounded transition-colors border border-slate-200"
                      title="Copy to clipboard"
                    >
                      {copiedId === detailsNode.id ? (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" className="text-green-600">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      ) : (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                        </svg>
                      )}
                    </button>
                  </div>
                </div>
                
                {detailsNode.type === 'user' && (
                  <div>
                    <label className="text-xs font-bold text-slate-400 uppercase">Principal Name</label>
                    <div className="text-sm text-slate-700">{detailsNode.userPrincipalName}</div>
                  </div>
                )}

                <div>
                  <label className="text-xs font-bold text-slate-400 uppercase">Description</label>
                  {detailsNode.description ? (
                    <p className="text-sm text-slate-600 italic">{detailsNode.description}</p>
                  ) : (
                    <p className="text-sm text-slate-400 italic">No description available.</p>
                  )}
                </div>
                
                {/* --- MEMBERS LIST SECTION --- */}
                <div className="pt-4 mt-2 border-t border-slate-200">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xs font-bold text-green-600 uppercase flex items-center gap-1">
                      <ArrowRightCircle size={12} />
                      Contains ({relations.members.length})
                    </h3>
                    {relations.members.length > 0 && (
                      <button
                        onClick={exportToCSV}
                        className="flex items-center gap-1 text-xs text-slate-600 hover:text-indigo-600 transition-colors p-1 hover:bg-slate-100 rounded"
                        title="Export to CSV"
                      >
                        <Download size={12} />
                        CSV
                      </button>
                    )}
                  </div>

                  {relations.members.length > 0 && (
                    <div className="mb-3 space-y-2">
                      {/* Member Type Breakdown */}
                      <div className="flex items-center gap-3 text-xs bg-slate-50 p-2 rounded border border-slate-200">
                        <div className="flex items-center gap-1">
                          <User size={10} className="text-emerald-500" />
                          <span className="font-medium">{relations.userCount}</span>
                          <span className="text-slate-500">Users</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Users size={10} className="text-blue-500" />
                          <span className="font-medium">{relations.groupCount}</span>
                          <span className="text-slate-500">Groups</span>
                        </div>
                      </div>

                      {/* Filter Input */}
                      <div className="relative">
                        <Filter className="absolute left-2 top-2 text-slate-400" size={12} />
                        <input
                          type="text"
                          className="w-full pl-7 pr-2 py-1.5 bg-white border border-slate-200 rounded text-xs focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-transparent transition-all"
                          placeholder="Filter members..."
                          value={memberFilter}
                          onChange={(e) => setMemberFilter(e.target.value)}
                        />
                        {memberFilter && (
                          <button
                            onClick={() => setMemberFilter('')}
                            className="absolute right-2 top-2 text-slate-400 hover:text-slate-600"
                          >
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <line x1="18" y1="6" x2="6" y2="18"></line>
                              <line x1="6" y1="6" x2="18" y2="18"></line>
                            </svg>
                          </button>
                        )}
                      </div>
                    </div>
                  )}

                  {relations.filteredMembers.length > 0 ? (
                    <div className="space-y-1 max-h-60 overflow-y-auto">
                      {relations.filteredMembers.map(member => (
                        <div 
                          key={member.id} 
                          className="flex items-center gap-2 p-2 rounded bg-slate-50 hover:bg-slate-100 cursor-pointer border border-transparent hover:border-slate-200 transition-colors"
                          onClick={() => setDetailsNode(member)}
                        >
                           {member.type === 'user' ? <User size={12} className="text-emerald-500"/> : <Users size={12} className="text-blue-500"/>}
                           <span className="text-xs text-slate-700 font-medium truncate">{member.displayName}</span>
                        </div>
                      ))}
                    </div>
                  ) : relations.members.length > 0 ? (
                     <p className="text-xs text-slate-400 italic">No members match "{memberFilter}"</p>
                  ) : (
                     <p className="text-xs text-slate-400 italic">No direct members.</p>
                  )}
                </div>

                {/* --- MEMBER OF SECTION --- */}
                <div className="pt-4 mt-2 border-t border-slate-200">
                  <h3 className="text-xs font-bold text-purple-600 uppercase mb-2 flex items-center gap-1">
                    <FolderOpen size={12} />
                    Member Of ({relations.parents.length})
                  </h3>
                  {relations.parents.length > 0 ? (
                    <div className="space-y-1">
                      {relations.parents.map(parent => (
                        <div 
                          key={parent.id} 
                          className="flex items-center gap-2 p-2 rounded bg-slate-50 hover:bg-slate-100 cursor-pointer border border-transparent hover:border-slate-200 transition-colors"
                          onClick={() => setDetailsNode(parent)}
                        >
                           <Users size={12} className="text-indigo-500"/>
                           <span className="text-xs text-slate-700 font-medium truncate">{parent.displayName}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                     <p className="text-xs text-slate-400 italic">No parent groups.</p>
                  )}
                </div>

                {/* Action Buttons */}
                {detailsNode.type === 'group' && (
                  <div className="pt-4 mt-4 border-t border-slate-100">
                     <button 
                      className="w-full py-2 bg-white border border-slate-200 shadow-sm rounded-md text-sm font-medium text-slate-600 hover:bg-slate-50 hover:text-indigo-600 transition-colors flex items-center justify-center gap-2"
                      onClick={() => setSelectedGroup(detailsNode)} // Recursively explore
                     >
                       <Layers size={14} />
                       Re-Focus Visualization
                     </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-400 text-center">
              <Shield size={48} className="mb-3 opacity-20" />
              <p className="text-sm">Select a group to visualize hierarchy</p>
              <p className="text-xs mt-2 opacity-60">Click nodes in the graph to view details</p>
            </div>
          )}
        </div>
        
        {/* Footer */}
        <div className="p-3 bg-slate-50 border-t border-slate-200 text-[10px] text-center text-slate-400">
           Azure AD Graph Explorer • {USE_MOCK_DATA ? 'Mock Mode Active' : 'Connected to API'}
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="flex-1 relative bg-slate-100 p-4">
        {error ? (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="bg-red-50 p-6 rounded-lg text-center max-w-md border border-red-100">
              <h3 className="text-red-700 font-bold mb-2">Connection Error</h3>
              <p className="text-red-600 text-sm">{error}</p>
              <button onClick={() => window.location.reload()} className="mt-4 px-4 py-2 bg-white border border-red-200 text-red-600 rounded shadow-sm text-sm hover:bg-red-50">Retry</button>
            </div>
          </div>
        ) : (
          <ForceGraph data={graphData} onNodeClick={setDetailsNode} />
        )}
      </div>

    </div>
  );
}
