// Package topology provides network topology management for Stella
package topology

import (
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

// PathFinder handles path finding algorithms for the network topology
type PathFinder struct {
	topology *TopologyManager
}

// NewPathFinder creates a new path finder instance
func NewPathFinder(topology *TopologyManager) *PathFinder {
	return &PathFinder{
		topology: topology,
	}
}

// FindShortestPath finds the shortest path between two nodes using Dijkstra's algorithm
func (pf *PathFinder) FindShortestPath(source, destination uuid.UUID) ([]uuid.UUID, error) {
	// Get all nodes from topology
	nodes := pf.topology.GetAllNodes()

	// Build adjacency list for the graph
	adjList := make(map[uuid.UUID]map[uuid.UUID]int)
	for _, node := range nodes {
		adjList[node.ID] = make(map[uuid.UUID]int)
	}

	// Build edges from paths
	paths := pf.topology.GetAllPaths()
	for _, path := range paths {
		if path.Active {
			// Use latency as edge weight, default to 1 if latency is 0
			weight := path.Latency
			if weight == 0 {
				weight = 1
			}
			// Add edge in both directions since network paths are bidirectional
			adjList[path.Source][path.Destination] = weight
			adjList[path.Destination][path.Source] = weight
		}
	}

	// Run Dijkstra's algorithm
	return dijkstra(adjList, source, destination)
}

// FindAllPaths finds all possible paths between two nodes with a maximum hop count
func (pf *PathFinder) FindAllPaths(source, destination uuid.UUID, maxHops int) [][]uuid.UUID {
	// Get all nodes from topology
	nodes := pf.topology.GetAllNodes()

	// Build adjacency list for the graph
	adjList := make(map[uuid.UUID]map[uuid.UUID]int)
	for _, node := range nodes {
		adjList[node.ID] = make(map[uuid.UUID]int)
	}

	// Build edges from paths
	paths := pf.topology.GetAllPaths()
	for _, path := range paths {
		if path.Active {
			adjList[path.Source][path.Destination] = 1 // Using hop count as weight
			adjList[path.Destination][path.Source] = 1
		}
	}

	// Find all paths
	var allPaths [][]uuid.UUID
	visited := make(map[uuid.UUID]bool)
	pf.findAllPathsDFS(source, destination, []uuid.UUID{source}, visited, maxHops, &allPaths, adjList)

	return allPaths
}

// findAllPathsDFS is a depth-first search implementation to find all paths
func (pf *PathFinder) findAllPathsDFS(current, destination uuid.UUID, path []uuid.UUID, visited map[uuid.UUID]bool, maxHops int, allPaths *[][]uuid.UUID, adjList map[uuid.UUID]map[uuid.UUID]int) {
	// Mark current node as visited
	visited[current] = true

	// If we've reached the destination, add the path to results
	if current == destination && len(path) > 1 {
		pathCopy := make([]uuid.UUID, len(path))
		copy(pathCopy, path)
		*allPaths = append(*allPaths, pathCopy)
		// Unmark before backtracking
		visited[current] = false
		return
	}

	// If we've exceeded max hops, backtrack
	if len(path) >= maxHops {
		visited[current] = false
		return
	}

	// Visit all neighbors
	for neighbor := range adjList[current] {
		if !visited[neighbor] {
			// Add neighbor to the path
			path = append(path, neighbor)
			// Recursively explore from neighbor
			pf.findAllPathsDFS(neighbor, destination, path, visited, maxHops, allPaths, adjList)
			// Backtrack: remove neighbor from path
			path = path[:len(path)-1]
		}
	}

	// Unmark before backtracking
	visited[current] = false
}

// UpdatePathLatency updates the latency for a path based on measurements
func (pf *PathFinder) UpdatePathLatency(path *Path, measuredLatency int) {
	// Apply exponential moving average for smoother latency updates
	if path.Latency == 0 {
		path.Latency = measuredLatency
	} else {
		// 70% weight to new measurement, 30% to old value
		path.Latency = int(float64(measuredLatency)*0.7 + float64(path.Latency)*0.3)
	}
	path.LastActive = time.Now()
	pf.topology.AddPath(path)
}

// GetPathQuality returns a quality score for a path (higher is better)
func (pf *PathFinder) GetPathQuality(path *Path) float64 {
	if !path.Active {
		return 0
	}

	// Base quality on latency (lower is better)
	latencyFactor := 100.0
	if path.Latency > 0 {
		// Inverse relationship with latency, capped at 100
		latencyFactor = math.Min(100.0, 1000.0/float64(path.Latency))
	}

	// Bonus for trusted paths
	trustedBonus := 0.0
	if path.Trusted {
		trustedBonus = 20.0
	}

	return latencyFactor + trustedBonus
}

// FindOptimalPath finds the path with the highest quality score between two nodes
func (pf *PathFinder) FindOptimalPath(source, destination uuid.UUID) (*Path, float64) {
	paths := pf.topology.GetAllPaths()
	var bestPath *Path
	var bestQuality float64

	for _, path := range paths {
		// Check if path connects the source and destination
		if (path.Source == source && path.Destination == destination) ||
		   (path.Source == destination && path.Destination == source) {
			quality := pf.GetPathQuality(path)
			if quality > bestQuality {
				bestQuality = quality
				bestPath = path
			}
		}
	}

	return bestPath, bestQuality
}

// Dijkstra's algorithm implementation
func dijkstra(adjList map[uuid.UUID]map[uuid.UUID]int, source, destination uuid.UUID) ([]uuid.UUID, error) {
	// Initialize distances
	dist := make(map[uuid.UUID]int)
	prev := make(map[uuid.UUID]uuid.UUID)
	visited := make(map[uuid.UUID]bool)

	// Set initial distances to infinity
	for node := range adjList {
		dist[node] = math.MaxInt32
	}
	dist[source] = 0

	// Create a priority queue of nodes to visit
	type nodeDistance struct {
		node     uuid.UUID
		distance int
	}
	queue := []nodeDistance{{source, 0}}

	for len(queue) > 0 {
		// Sort queue by distance (smallest first)
		sort.Slice(queue, func(i, j int) bool {
			return queue[i].distance < queue[j].distance
		})

		// Get the node with the smallest distance
		current := queue[0]
		queue = queue[1:]

		// If we've already visited this node, skip it
		if visited[current.node] {
			continue
		}

		// Mark node as visited
		visited[current.node] = true

		// If we've reached the destination, we're done
		if current.node == destination {
			break
		}

		// Relax edges to neighbors
		for neighbor, weight := range adjList[current.node] {
			if !visited[neighbor] {
				newDist := dist[current.node] + weight
				if newDist < dist[neighbor] {
					dist[neighbor] = newDist
					prev[neighbor] = current.node
					queue = append(queue, nodeDistance{neighbor, newDist})
				}
			}
		}
	}

	// Reconstruct the shortest path
	if dist[destination] == math.MaxInt32 {
		// No path found
		return nil, nil
	}

	path := []uuid.UUID{destination}
	for current := destination; current != source; current = prev[current] {
		path = append([]uuid.UUID{prev[current]}, path...)
	}

	return path, nil
}

// OptimizePath optimizes a path by checking for direct connections between nodes
func (pf *PathFinder) OptimizePath(path []uuid.UUID) []uuid.UUID {
	if len(path) <= 2 {
		// Path is already optimal
		return path
	}

	optimized := []uuid.UUID{path[0]}
	current := path[0]

	// Try to find direct connections that can bypass intermediate nodes
	for i := 1; i < len(path)-1; i++ {
		// Check if there's a direct path from current to path[i+1]
		directPath, exists := pf.topology.GetPath(current, path[i+1])
		if exists && directPath.Active {
			// Skip path[i] and connect directly to path[i+1]
			optimized = append(optimized, path[i+1])
			current = path[i+1]
			// Skip next iteration since we've already handled it
			i++
		} else {
			// Keep the current node
			optimized = append(optimized, path[i])
			current = path[i]
		}
	}

	// Add the last node if not already added
	if len(optimized) == 0 || optimized[len(optimized)-1] != path[len(path)-1] {
		optimized = append(optimized, path[len(path)-1])
	}

	return optimized
}