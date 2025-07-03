// Standalone Project File Browser

// Parse project parameter from URL
const urlParams = new URLSearchParams(window.location.search);
const project = urlParams.get('project');
const initialFile = urlParams.get('file');
const highlightLineParam = urlParams.get('line');

const projectNameHeader = document.getElementById('projectName');
const directoryListing = document.getElementById('directoryListing');
const codeViewer = document.getElementById('codeViewer');
const copyCodeBtn = document.getElementById('copyCodeBtn');
const filePathHeader = document.getElementById('filePathHeader');

let currentPath = '';

// Initialize
(async function init() {
    if (!project) {
        directoryListing.innerHTML = '<div class="text-danger text-center py-4">Missing project parameter in URL.</div>';
        return;
    }

    projectNameHeader.textContent = project;

    // Determine initial directory
    let initialDir = '';
    if (initialFile && initialFile.includes('/')) {
        initialDir = initialFile.substring(0, initialFile.lastIndexOf('/'));
    }

    await loadDirectory(initialDir);

    // If an initial file is specified, open it after directory loads
    if (initialFile) {
        openFile(initialFile, highlightLineParam);
    }

    copyCodeBtn.addEventListener('click', copySourceCode);
})();

// Load directory contents
async function loadDirectory(path = '') {
    currentPath = path;
    directoryListing.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    try {
        const response = await fetch(`/api/dir?project=${encodeURIComponent(project)}&path=${encodeURIComponent(path)}`);
        if (!response.ok) {
            throw new Error(`Failed to load directory: ${response.status} ${response.statusText}`);
        }
        const dirData = await response.json();
        displayDirectory(dirData);
    } catch (error) {
        console.error('Error loading directory:', error);
        directoryListing.innerHTML = `<div class="text-danger text-center py-4">${error.message}</div>`;
    }
}

// Display directory listing
function displayDirectory(dirData) {
    const { path, directories, files } = dirData;
    let html = '<ul class="list-group">';
    // Parent link
    if (path && path !== '') {
        const parentPath = path.split('/').slice(0, -1).join('/');
        html += `<li class="list-group-item directory-item" onclick="navigateDirectory('${encodeURIComponent(parentPath)}')"><i class="fas fa-level-up-alt"></i> ..</li>`;
    }
    // Directories first
    directories.forEach(dir => {
        const newPath = path ? `${path}/${dir}` : dir;
        html += `<li class="list-group-item directory-item" onclick="navigateDirectory('${encodeURIComponent(newPath)}')"><i class="fas fa-folder"></i> ${dir}</li>`;
    });
    // Files
    files.forEach(file => {
        const filePath = path ? `${path}/${file}` : file;
        html += `<li class="list-group-item file-item" onclick="openFile('${encodeURIComponent(filePath)}')"><i class="fas fa-file"></i> ${file}</li>`;
    });
    html += '</ul>';
    directoryListing.innerHTML = html;
}

// Navigate directory
function navigateDirectory(encodedPath) {
    const path = decodeURIComponent(encodedPath);
    loadDirectory(path);
}

// Open file and display source code
async function openFile(encodedFilePath, highlightLine = null) {
    const filePath = decodeURIComponent(encodedFilePath);
    codeViewer.innerHTML = '<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    try {
        const response = await fetch(`/api/source/${encodeURIComponent(project)}/${encodeURIComponent(filePath)}`);
        if (!response.ok) {
            throw new Error(`Failed to load source code: ${response.status} ${response.statusText}`);
        }
        const sourceData = await response.json();
        if (sourceData.content) {
            // Use highlight.js to highlight
            let highlighted;
            try {
                highlighted = hljs.highlightAuto(sourceData.content).value;
            } catch (e) {
                highlighted = sourceData.content.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
            }

            const lines = highlighted.split('\n');
            let html = '';
            lines.forEach((line, idx) => {
                const lineNo = idx + 1;
                const isHighlight = highlightLine && lineNo === parseInt(highlightLine);
                html += `<div class="code-line ${isHighlight ? 'highlighted-line' : ''}"><span class="line-number">${lineNo}</span> <span class="line-content">${line}</span></div>`;
            });
            codeViewer.innerHTML = html;
            copyCodeBtn.disabled = false;
            filePathHeader.textContent = filePath;
            // Scroll to highlighted line
            if (highlightLine) {
                setTimeout(() => {
                    const el = codeViewer.querySelectorAll('.code-line')[highlightLine - 1];
                    if (el) {
                        el.scrollIntoView({behavior:'instant', block:'center'});
                    }
                }, 100);
            }
        } else {
            codeViewer.innerHTML = '<div class="text-muted text-center py-4">Source code not available</div>';
            copyCodeBtn.disabled = true;
        }
    } catch (error) {
        console.error('Error loading source code:', error);
        codeViewer.innerHTML = `<div class="text-danger text-center py-4">${error.message}</div>`;
        copyCodeBtn.disabled = true;
    }
}

// Copy code to clipboard
function copySourceCode() {
    const text = codeViewer.textContent;
    navigator.clipboard.writeText(text).then(() => {
        copyCodeBtn.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
            copyCodeBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 1500);
    }).catch(err => console.error('Copy failed:', err));
}
