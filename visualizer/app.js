// Global variables
let config = {};
let currentProject = '';
let currentCWE = '';
let currentModel = '';
let currentTrace = null;
let sarifData = null;

// Cache for snippets to avoid refetching files
const snippetCache = {};

// DOM elements
const projectSelect = document.getElementById('projectSelect');
const cweSelect = document.getElementById('cweSelect');
const modelSelect = document.getElementById('modelSelect');
const traceSelect = document.getElementById('traceSelect');
const irisResults = document.getElementById('irisResults');
const traceDetails = document.getElementById('traceDetails');
const codeFlow = document.getElementById('codeFlow');
const sourceCode = document.getElementById('sourceCode');
const copyCodeBtn = document.getElementById('copyCodeBtn');
const projectMetadata = document.getElementById('projectMetadata');

// Initialize the application
async function init() {
    try {
        // Load configuration
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error('Failed to load configuration');
        }
        config = await response.json();
        
        // Load projects on startup
        await loadProjects();
        
        // Set up event listeners
        setupEventListeners();
        
        console.log('IRIS Visualizer initialized successfully');
    } catch (error) {
        console.error('Initialization error:', error);
        showError('Failed to initialize application: ' + error.message);
    }
}

// Set up event listeners
function setupEventListeners() {
    projectSelect.addEventListener('change', onProjectChange);
    cweSelect.addEventListener('change', onCWEChange);
    modelSelect.addEventListener('change', onModelChange);
    traceSelect.addEventListener('change', onTraceChange);
    copyCodeBtn.addEventListener('click', copySourceCode);
}

// Load projects
async function loadProjects() {
    try {
        const response = await fetch('/api/projects');
        if (!response.ok) {
            throw new Error(`Failed to load projects: ${response.status} ${response.statusText}`);
        }
        
        const projects = await response.json();
        console.log('Loaded projects from outputs:', projects);
        
        // Clear and populate project select
        projectSelect.innerHTML = '<option value="">Select a project...</option>';
        projects.forEach(project => {
            const option = document.createElement('option');
            option.value = project;
            option.textContent = project;
            projectSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading projects:', error);
        showError('Failed to load projects: ' + error.message);
    }
}

// Handle project selection
async function onProjectChange() {
    currentProject = projectSelect.value;
    currentCWE = '';
    currentModel = '';
    currentTrace = null;
    
    // Reset dependent dropdowns
    cweSelect.innerHTML = '<option value="">Select a CWE...</option>';
    modelSelect.innerHTML = '<option value="">Select a run-id...</option>';
    traceSelect.innerHTML = '<option value="">Select a trace...</option>';
    
    cweSelect.disabled = !currentProject;
    modelSelect.disabled = !currentProject;
    traceSelect.disabled = true;
    
    // Clear panels (including project metadata since project changed)
    clearPanels(true);
    
    if (currentProject) {
        await loadProjectData();
        await loadProjectMetadata();
    }
}

// Load project data (CWEs and run-ids)
async function loadProjectData() {
    try {
        // Load CWEs and run-ids in parallel
        const [cweResponse, modelResponse] = await Promise.all([
            fetch(`/api/project_cwes?project=${encodeURIComponent(currentProject)}`),
            fetch(`/api/models?project=${encodeURIComponent(currentProject)}`)
        ]);
        
        if (!cweResponse.ok) {
            throw new Error(`Failed to load CWEs: ${cweResponse.status} ${cweResponse.statusText}`);
        }
        if (!modelResponse.ok) {
            throw new Error(`Failed to load run-ids: ${modelResponse.status} ${modelResponse.statusText}`);
        }
        
        const [cwes, models] = await Promise.all([
            cweResponse.json(),
            modelResponse.json()
        ]);
        
        // Populate CWE select
        cweSelect.innerHTML = '<option value="">Select a CWE...</option>';
        cwes.forEach(cwe => {
            const option = document.createElement('option');
            option.value = cwe;
            option.textContent = cwe;
            cweSelect.appendChild(option);
        });
        
        // Populate model select
        modelSelect.innerHTML = '<option value="">Select a run-id...</option>';
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model;
            option.textContent = model;
            modelSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading project data:', error);
        showError('Failed to load project data: ' + error.message);
    }
}

// Handle CWE selection
async function onCWEChange() {
    currentCWE = cweSelect.value;
    currentModel = '';
    currentTrace = null;
    
    // Reset dependent dropdowns
    modelSelect.innerHTML = '<option value="">Select a run-id...</option>';
    traceSelect.innerHTML = '<option value="">Select a trace...</option>';
    
    modelSelect.disabled = !currentCWE;
    traceSelect.disabled = true;
    
    // Clear panels except project metadata
    clearPanels(false);
    
    if (currentCWE) {
        await loadModelsForCWE();
    }
}

// Load run-ids for the selected CWE (optimized)
async function loadModelsForCWE() {
    try {
        const response = await fetch(`/api/models?project=${encodeURIComponent(currentProject)}`);
        if (!response.ok) {
            throw new Error(`Failed to load run-ids: ${response.status} ${response.statusText}`);
        }
        
        const models = await response.json();
        
        // Check which run-ids have SARIF data for this CWE in parallel
        const modelChecks = models.map(async (model) => {
            const sarifPath = `${currentProject}/${model}/${currentCWE}/results.sarif`;
            try {
                const sarifResponse = await fetch(`/api/sarif/${encodeURIComponent(sarifPath)}`);
                return sarifResponse.ok ? model : null;
            } catch (error) {
                return null;
            }
        });
        
        const modelResults = await Promise.all(modelChecks);
        const availableModels = modelResults.filter(model => model !== null);
        
        // Populate model select
        modelSelect.innerHTML = '<option value="">Select a run-id...</option>';
        availableModels.forEach(model => {
            const option = document.createElement('option');
            option.value = model;
            option.textContent = model;
            modelSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading run-ids:', error);
        showError('Failed to load run-ids: ' + error.message);
    }
}

// Handle run-id selection
async function onModelChange() {
    currentModel = modelSelect.value;
    currentTrace = null;
    
    // Reset trace dropdown
    traceSelect.innerHTML = '<option value="">Select a trace...</option>';
    traceSelect.disabled = !currentModel;
    
    // Clear panels except project metadata
    clearPanels(false);
    
    if (currentModel) {
        await loadTraces();
    }
}

// Load traces for the selected run-id and CWE
async function loadTraces() {
    try {
        const sarifPath = `${currentProject}/${currentModel}/${currentCWE}/results.sarif`;
        const response = await fetch(`/api/sarif/${encodeURIComponent(sarifPath)}`);
        
        if (!response.ok) {
            throw new Error(`Failed to load SARIF data: ${response.status} ${response.statusText}`);
        }
        
        sarifData = await response.json();
        
        // Extract traces from SARIF data
        const traces = extractTraces(sarifData);
        
        // Populate trace select
        traceSelect.innerHTML = '<option value="">Select a trace...</option>';
        traces.forEach((trace, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = `Trace ${index + 1}: ${trace.ruleId || 'Unknown Rule'}`;
            traceSelect.appendChild(option);
        });
        
        // Display IRIS results summary
        displayIRISResults(traces);
        
        traceSelect.disabled = false;
    } catch (error) {
        console.error('Error loading traces:', error);
        showError('Failed to load traces: ' + error.message);
    }
}

// Handle trace selection
async function onTraceChange() {
    const traceIndex = parseInt(traceSelect.value);
    
    if (traceIndex >= 0 && sarifData) {
        const traces = extractTraces(sarifData);
        currentTrace = traces[traceIndex];
        
        displayTraceDetails(currentTrace);
        displayCodeFlow(currentTrace);
    } else {
        clearPanels();
    }
}

// Extract traces from SARIF data
function extractTraces(sarifData) {
    const traces = [];
    
    if (sarifData.runs && sarifData.runs.length > 0) {
        const run = sarifData.runs[0];
        
        if (run.results && run.results.length > 0) {
            run.results.forEach(result => {
                if (result.codeFlows && result.codeFlows.length > 0) {
                    result.codeFlows.forEach(codeFlow => {
                        if (codeFlow.threadFlows && codeFlow.threadFlows.length > 0) {
                            codeFlow.threadFlows.forEach(threadFlow => {
                                const trace = {
                                    ruleId: result.ruleId,
                                    message: result.message?.text || 'No message',
                                    level: result.level || 'warning',
                                    locations: threadFlow.locations || [],
                                    sarifResult: result,
                                    sarifRun: run
                                };
                                traces.push(trace);
                            });
                        }
                    });
                }
            });
        }
    }
    
    return traces;
}

// Display IRIS results summary
function displayIRISResults(traces) {
    const summary = {
        totalTraces: traces.length,
        byLevel: {},
        byRule: {}
    };
    
    traces.forEach(trace => {
        // Count by level
        summary.byLevel[trace.level] = (summary.byLevel[trace.level] || 0) + 1;
        
        // Count by rule
        summary.byRule[trace.ruleId] = (summary.byRule[trace.ruleId] || 0) + 1;
    });
    
    let html = `
        <div class="iris-summary">
            <div class="row">
                <div class="col-md-3">
                    <div class="summary-card">
                        <h6>Total Traces</h6>
                        <div class="summary-value">${summary.totalTraces}</div>
                    </div>
                </div>
                <div class="col-md-9">
                    <div class="summary-breakdown">
                        <h6>By Severity Level</h6>
                        <div class="severity-bars">
    `;
    
    Object.entries(summary.byLevel).forEach(([level, count]) => {
        const percentage = ((count / summary.totalTraces) * 100).toFixed(1);
        const severityClass = level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'low';
        html += `
            <div class="severity-bar">
                <span class="severity-label">${level.toUpperCase()}</span>
                <div class="progress">
                    <div class="progress-bar bg-${severityClass}" style="width: ${percentage}%"></div>
                </div>
                <span class="severity-count">${count}</span>
            </div>
        `;
    });
    
    html += `
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    //irisResults.innerHTML = html;
}

// Display trace details
function displayTraceDetails(trace) {
    const metadata = extractMetadata(trace);
    
    let html = `
        <div class="trace-meta">
            <h6><i class="fas fa-info-circle"></i> Trace Metadata</h6>
            <div class="meta-item">
                <span class="meta-label">Rule ID:</span>
                <span class="meta-value">${metadata.ruleId}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Severity:</span>
                <span class="meta-value">
                    <span class="badge severity-${metadata.severity}">${metadata.severity.toUpperCase()}</span>
                </span>
            </div>
            <div class="meta-item">
                <span class="meta-label">CodeQL Version:</span>
                <span class="meta-value">${metadata.codeqlVersion}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">QL Pack:</span>
                <span class="meta-value">${metadata.qlpack}</span>
            </div>
        </div>
        
        <div class="trace-message">
            <h6><i class="fas fa-comment"></i> Message</h6>
            <p>${escapeHtml(trace.message)}</p>
        </div>
    `;
    
    traceDetails.innerHTML = html;
}

// Extract metadata from trace
function extractMetadata(trace) {
    console.log('Extracting metadata for trace:', trace.ruleId);
    console.log('SARIF run tool:', trace.sarifRun.tool);
    console.log('SARIF result:', trace.sarifResult);
    
    const metadata = {
        ruleId: trace.ruleId || 'Unknown',
        severity: 'warning', // default
        codeqlVersion: 'Unknown',
        qlpack: 'Unknown'
    };
    
    // Extract CodeQL version from tool driver
    if (trace.sarifRun.tool && trace.sarifRun.tool.driver) {
        metadata.codeqlVersion = trace.sarifRun.tool.driver.semanticVersion || 'Unknown';
        console.log('CodeQL version from driver:', metadata.codeqlVersion);
    }
    
    // Extract QL pack from tool extensions
    if (trace.sarifRun.tool && trace.sarifRun.tool.extensions) {
        console.log('Tool extensions:', trace.sarifRun.tool.extensions);
        for (const ext of trace.sarifRun.tool.extensions) {
            // fetch the uri field in the extensions and assign it to metadata.qlpack
            if (ext.locations && ext.locations.length > 0) {
                metadata.qlpack = ext.locations[0].uri;
                console.log('QL pack URI found:', metadata.qlpack);
                break;
            }
            // if (ext.name &&  ext.name.startsWith('codeql/')) {
            //     metadata.qlpack = ext.name;
            //     console.log('QL pack found:', metadata.qlpack);
            //     break;
            // }
        }
    }
    
    // Extract severity from the SARIF result itself (this is where security-severity is)
    if (trace.sarifResult) {
        // Try to get security severity from result properties first
        if (trace.sarifResult.properties && trace.sarifResult.properties['security-severity']) {
            const securitySeverity = parseFloat(trace.sarifResult.properties['security-severity']);
            console.log('Security severity from result properties:', securitySeverity);
            if (securitySeverity >= 7.0) {
                metadata.severity = 'error';
            } else if (securitySeverity >= 4.0) {
                metadata.severity = 'warning';
            } else {
                metadata.severity = 'note';
            }
            console.log('Severity from security-severity:', metadata.severity);
        }
        
        // Try to get severity from result level as fallback
        if (trace.sarifResult.level && metadata.severity === 'warning') {
            metadata.severity = trace.sarifResult.level;
            console.log('Severity from result level:', metadata.severity);
        }
    }
    
    // Fallback: try to get severity from rule configuration in tool driver
    if (trace.sarifRun.tool && trace.sarifRun.tool.driver && trace.sarifRun.tool.driver.rules) {
        const rule = trace.sarifRun.tool.driver.rules.find(r => r.id === trace.ruleId);
        console.log('Found rule in driver:', rule);
        if (rule) {
            // Try to get severity from defaultConfiguration
            if (rule.defaultConfiguration && rule.defaultConfiguration.level) {
                metadata.severity = rule.defaultConfiguration.level;
                console.log('Severity from defaultConfiguration:', metadata.severity);
            }
            
            // Try to get security severity from properties
            if (rule.properties && rule.properties['security-severity']) {
                const securitySeverity = parseFloat(rule.properties['security-severity']);
                console.log('Security severity from rule properties:', securitySeverity);
                if (securitySeverity >= 7.0) {
                    metadata.severity = 'error';
                } else if (securitySeverity >= 4.0) {
                    metadata.severity = 'warning';
                } else {
                    metadata.severity = 'note';
                }
                console.log('Severity from security-severity:', metadata.severity);
            }
        }
    }
    
    console.log('Final metadata:', metadata);
    return metadata;
}

// Display code flow
function displayCodeFlow(trace) {
    let html = '';
    const contextLines = 2; // lines before and after
    
    if (trace.locations && trace.locations.length > 0) {
        trace.locations.forEach((location, index) => {
            const step = location.location;
            const message = step.message?.text || `Step ${index + 1}`;
            const filePath = step.physicalLocation?.artifactLocation?.uri || 'Unknown file';
            const lineNumber = step.physicalLocation?.region?.startLine || '?';
            
            html += `
                <div class="code-flow-step" data-step="${index}" onclick="selectCodeFlowStep(${index})">
                    <div class="step-number">${index + 1}</div>
                    <div class="step-content">
                        <div class="step-title">
                            ${escapeHtml(message)}
                            <a href="file_browser.html?project=${encodeURIComponent(currentProject)}&file=${encodeURIComponent(filePath)}&line=${lineNumber}" target="_blank" class="external-link" onclick="event.stopPropagation();" title="Open in file browser">
                                <i class="fas fa-external-link-alt"></i>
                            </a>
                        </div>
                        <div class="step-location">
                            <span class="file-link">
                                ${escapeHtml(filePath)}:${lineNumber}
                            </span>
                        </div>
                        <pre id="snippet-${index}" class="code-snippet">Loading snippet...</pre>
                    </div>
                </div>
            `;
        });
    } else {
        html = '<div class="text-muted text-center py-4">No code flow information available</div>';
    }
    
    codeFlow.innerHTML = html;

    // After rendering, load snippets asynchronously
    if (trace.locations && trace.locations.length > 0) {
        trace.locations.forEach((location, idx) => {
            const step = location.location;
            const filePath = step.physicalLocation?.artifactLocation?.uri;
            const lineNumber = step.physicalLocation?.region?.startLine;
            if (filePath && lineNumber) {
                loadSnippet(filePath, lineNumber, idx, contextLines);
            }
        });
    }
}

// Select code flow step
function selectCodeFlowStep(stepIndex) {
    // Remove active class from all steps
    document.querySelectorAll('.code-flow-step').forEach(step => {
        step.classList.remove('active');
    });
    
    // Add active class to selected step
    const selectedStep = document.querySelector(`[data-step="${stepIndex}"]`);
    if (selectedStep) {
        selectedStep.classList.add('active');
    }
    
    // Load source code for the selected step
    if (currentTrace && currentTrace.locations[stepIndex]) {
        loadSourceCode(currentTrace.locations[stepIndex].location);
    }
}

// Load source code
async function loadSourceCode(location) {
    try {
        const filePath = location.physicalLocation?.artifactLocation?.uri;
        const lineNumber = location.physicalLocation?.region?.startLine;
        
        if (!filePath) {
            sourceCode.innerHTML = '<div class="text-muted text-center py-4">No source file information available</div>';
            return;
        }
        
        // Include project name in the path as expected by the server
        const response = await fetch(`/api/source/${encodeURIComponent(currentProject)}/${encodeURIComponent(filePath)}`);
        
        if (!response.ok) {
            throw new Error(`Failed to load source code: ${response.status} ${response.statusText}`);
        }
        
        const sourceData = await response.json();
        
        if (sourceData.content) {
            displaySourceCode(sourceData.content, lineNumber, filePath, sourceData.project);
            copyCodeBtn.disabled = false;
        } else {
            sourceCode.innerHTML = '<div class="text-muted text-center py-4">Source code not available</div>';
            copyCodeBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error loading source code:', error);
        sourceCode.innerHTML = `<div class="text-danger text-center py-4">Error loading source code: ${error.message}</div>`;
        copyCodeBtn.disabled = true;
    }
}

// Display source code
function displaySourceCode(content, highlightLine, filePath, sourceProject) {
    // Use highlight.js to add syntax highlighting
    let highlightedContent;
    try {
        highlightedContent = hljs.highlightAuto(content).value;
    } catch (e) {
        highlightedContent = escapeHtml(content);
    }

    const lines = highlightedContent.split('\n');
    let html = `
        <div class="source-code-container">
            <div class="code-header">
                <span class="file-name">${escapeHtml(filePath)}</span>
                ${highlightLine ? `<span class="line-info">Highlighted line: ${highlightLine}</span>` : ''}
                <span class="project-info">Source: ${escapeHtml(sourceProject)}</span>
            </div>
            <div class="code-content">
    `;
    
    lines.forEach((line, index) => {
        const lineNumber = index + 1;
        const isHighlighted = lineNumber === parseInt(highlightLine);
        const lineClass = isHighlighted ? 'highlighted-line' : '';
        
        html += `
            <div class="code-line ${lineClass}" id="line-${lineNumber}">
                <span class="line-number">${lineNumber}</span>
                <span class="line-content">${line}</span>
            </div>
        `;
    });
    
    html += `
            </div>
        </div>
    `;
    
    sourceCode.innerHTML = html;
    
    // Scroll to highlighted line within the source code container
    if (highlightLine) {
        setTimeout(() => {
            const highlightedElement = document.getElementById(`line-${highlightLine}`);
            const codeContent = sourceCode.querySelector('.code-content');
            
            if (highlightedElement && codeContent) {
                // Scroll the code content container to the highlighted line
                highlightedElement.scrollIntoView({ 
                    behavior: 'instant', 
                    block: 'center',
                    inline: 'nearest'
                });
            }
        }, 100);
    }
}

// Copy source code
function copySourceCode() {
    const codeContent = sourceCode.querySelector('.code-content');
    if (codeContent) {
        const text = Array.from(codeContent.querySelectorAll('.line-content'))
            .map(span => span.textContent)
            .join('\n');
        
        navigator.clipboard.writeText(text).then(() => {
            // Show temporary success message
            const originalText = copyCodeBtn.innerHTML;
            copyCodeBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            copyCodeBtn.classList.remove('btn-outline-secondary');
            copyCodeBtn.classList.add('btn-success');
            
            setTimeout(() => {
                copyCodeBtn.innerHTML = originalText;
                copyCodeBtn.classList.remove('btn-success');
                copyCodeBtn.classList.add('btn-outline-secondary');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            showError('Failed to copy source code');
        });
    }
}

// Load project metadata
async function loadProjectMetadata() {
    try {
        console.log('Loading metadata for project:', currentProject);
        const response = await fetch(`/api/project_metadata/${encodeURIComponent(currentProject)}`);
        
        if (!response.ok) {
            if (response.status === 404) {
                console.log('Project metadata not found for:', currentProject);
                displayProjectMetadata(null);
            } else {
                throw new Error(`Failed to load project metadata: ${response.status} ${response.statusText}`);
            }
            return;
        }
        
        const metadata = await response.json();
        console.log('Loaded metadata:', metadata);
        displayProjectMetadata(metadata);
    } catch (error) {
        console.error('Error loading project metadata:', error);
        displayProjectMetadata(null);
    }
}

// Display project metadata
function displayProjectMetadata(metadata) {
    if (!metadata) {
        projectMetadata.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> No metadata available for this project</div>';
        return;
    }
    
    let html = '<div class="metadata-grid">';
    
    // CVE Information
    html += `
        <div class="metadata-item">
            <div class="metadata-label">CVE ID</div>
            <div class="metadata-value ${metadata.cve_id ? '' : 'none'}">
                ${metadata.cve_id || 'None'}
            </div>
        </div>
    `;
    
    // CWE Information
    html += `
        <div class="metadata-item">
            <div class="metadata-label">CWE ID</div>
            <div class="metadata-value ${metadata.cwe_id ? '' : 'none'}">
                ${metadata.cwe_id || 'None'}
            </div>
        </div>
    `;
    
    html += `
        <div class="metadata-item">
            <div class="metadata-label">CWE Name</div>
            <div class="metadata-value ${metadata.cwe_name ? '' : 'none'}">
                ${metadata.cwe_name || 'None'}
            </div>
        </div>
    `;
    
    // GitHub Information
    html += `
        <div class="metadata-item">
            <div class="metadata-label">GitHub Repository</div>
            <div class="metadata-value ${metadata.github_url ? '' : 'none'}">
                ${metadata.github_url ? `<a href="${metadata.github_url}" target="_blank">${metadata.github_username}/${metadata.github_repository_name}</a>` : 'None'}
            </div>
        </div>
    `;
    
    html += `
        <div class="metadata-item">
            <div class="metadata-label">GitHub Tag</div>
            <div class="metadata-value ${metadata.github_tag ? '' : 'none'}">
                ${metadata.github_tag || 'None'}
            </div>
        </div>
    `;
    
    // Advisory Information
    html += `
        <div class="metadata-item">
            <div class="metadata-label">Advisory ID</div>
            <div class="metadata-value ${metadata.advisory_id ? '' : 'none'}">
                ${metadata.advisory_id || 'None'}
            </div>
        </div>
    `;
    
    // Commit Information
    html += `
        <div class="metadata-item">
            <div class="metadata-label">Buggy Commit</div>
            <div class="metadata-value ${metadata.buggy_commit_id ? '' : 'none'}">
                ${metadata.buggy_commit_id ? `<a href="${metadata.github_url}/commit/${metadata.buggy_commit_id}" target="_blank">${metadata.buggy_commit_id.substring(0, 8)}...</a>` : 'None'}
            </div>
        </div>
    `;
    
    html += `
        <div class="metadata-item">
            <div class="metadata-label">Fix Commits</div>
            <div class="metadata-value ${metadata.fix_commit_ids ? '' : 'none'}">
                ${metadata.fix_commit_ids ? metadata.fix_commit_ids.split(';').map(commit => 
                    `<a href="${metadata.github_url}/commit/${commit}" target="_blank">${commit.substring(0, 8)}...</a>`
                ).join(', ') : 'None'}
            </div>
        </div>
    `;
    
    html += '</div>';
    
    projectMetadata.innerHTML = html;
}

// Clear all panels
function clearPanels(clearProjectMetadata = true) {
    //irisResults.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> Select a project, CWE, and model to view results</div>';
    if (clearProjectMetadata) {
        projectMetadata.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> Select a project to view metadata</div>';
    }
    traceDetails.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> Select a trace to view details</div>';
    codeFlow.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> Select a trace to view code flow</div>';
    sourceCode.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-info-circle"></i> Click on a code flow step to view source code</div>';
    copyCodeBtn.disabled = true;
}

// Show error message
function showError(message) {
    // Create a simple error alert
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        <strong>Error:</strong> ${escapeHtml(message)}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Utility function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', init);

async function loadSnippet(filePath, lineNumber, index, context) {
    const cacheKey = `${filePath}`;
    if (!snippetCache[cacheKey]) {
        try {
            const resp = await fetch(`/api/source/${encodeURIComponent(currentProject)}/${encodeURIComponent(filePath)}`);
            if (!resp.ok) throw new Error('fetch failed');
            const data = await resp.json();
            snippetCache[cacheKey] = data.content.split('\n');
        } catch (e) {
            snippetCache[cacheKey] = null;
        }
    }
    const linesArr = snippetCache[cacheKey];
    const snippetEl = document.getElementById(`snippet-${index}`);
    if (!snippetEl) return;
    if (!linesArr) {
        snippetEl.textContent = 'Unable to load source.';
        return;
    }
    const start = Math.max(0, lineNumber - context - 1);
    const end = Math.min(linesArr.length, lineNumber + context);
    const snippetLines = linesArr.slice(start, end).map((ln,i) => {
        const num = start + i + 1;
        const content = ln;
        const prefix = num === lineNumber ? '>> ' : '   ';
        return `${prefix}${num.toString().padStart(4,' ')} | ${content}`;
    }).join('\n');

    // Highlight using hljs
    let highlighted;
    try {
        highlighted = hljs.highlightAuto(snippetLines).value;
    } catch {
        highlighted = escapeHtml(snippetLines);
    }
    snippetEl.innerHTML = highlighted;
}
