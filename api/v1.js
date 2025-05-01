const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const child_process = require('child_process');
const os = require('os');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuración de Multer para subida de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Base de datos de firmas de malware (en un sistema real sería una DB externa)
const malwareSignatures = [
  { signature: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', name: 'EICAR Test File' },
  { signature: '4D5A90000300000004000000FFFF0000', name: 'Portable Executable Header' },
  { signature: '6D616C77617265207369676E6174757265', name: 'Generic Malware Signature' }, // "malware signature" en hex
  { signature: '72616E736F6D77617265', name: 'Ransomware Marker' }, // "ransomware" en hex
  { signature: '7573657233322E646C6C', name: 'Suspicious DLL' } // "user32.dll" en hex
];

// Analizador avanzado de archivos
class AdvancedFileAnalyzer {
  constructor() {
    this.scanProgress = 0;
    this.totalFiles = 0;
    this.scannedFiles = 0;
    this.threatsFound = [];
    this.quarantineDir = path.join(__dirname, 'quarantine');
    
    if (!fs.existsSync(this.quarantineDir)) {
      fs.mkdirSync(this.quarantineDir, { recursive: true });
    }
  }

  // Calcular hash de archivo
  async calculateFileHash(filePath, algorithm = 'sha256') {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(algorithm);
      const stream = fs.createReadStream(filePath);

      stream.on('error', err => reject(err));
      stream.on('data', chunk => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }

  // Escanear archivo individual
  async scanFile(filePath) {
    try {
      const fileContent = await fs.promises.readFile(filePath);
      const fileHash = await this.calculateFileHash(filePath);
      
      // 1. Verificación por firmas conocidas
      for (const { signature, name } of malwareSignatures) {
        if (fileContent.includes(signature) || fileHash === signature) {
          return { 
            isMalicious: true, 
            threatName: name,
            filePath,
            fileHash
          };
        }
      }

      // 2. Análisis heurístico avanzado
      const heuristicsResult = this.heuristicAnalysis(filePath, fileContent);
      if (heuristicsResult.isMalicious) {
        return heuristicsResult;
      }

      // 3. Verificación de tipo MIME vs extensión
      const mimeCheck = this.checkMimeTypeConsistency(filePath);
      if (mimeCheck.isMalicious) {
        return mimeCheck;
      }

      return { isMalicious: false, filePath, fileHash };

    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
      return { isMalicious: false, error: error.message, filePath };
    }
  }

  // Análisis heurístico avanzado
  heuristicAnalysis(filePath, fileContent) {
    const fileStr = fileContent.toString();
    const extension = path.extname(filePath).toLowerCase();
    
    // Detección de scripts maliciosos
    if (extension === '.js' || extension === '.vbs' || extension === '.ps1') {
      const suspiciousPatterns = [
        'eval(', 'Function(', 'ActiveXObject', 'WScript.Shell',
        'Shell.Application', 'Scripting.FileSystemObject',
        'Start-Process', 'Invoke-Expression', 'DownloadFile'
      ];

      const foundPatterns = suspiciousPatterns.filter(pattern => 
        fileStr.includes(pattern)
      );

      if (foundPatterns.length > 3) {
        return {
          isMalicious: true,
          threatName: 'Suspicious Script',
          filePath,
          indicators: foundPatterns
        };
      }
    }

    // Detección de ejecutables maliciosos
    if (extension === '.exe' || extension === '.dll') {
      const peHeader = fileContent.slice(0, 2).toString();
      if (peHeader === 'MZ') {
        // Análisis básico de PE header
        const suspiciousImports = [
          'VirtualAlloc', 'CreateRemoteThread', 
          'WriteProcessMemory', 'LoadLibrary'
        ].filter(api => fileStr.includes(api));

        if (suspiciousImports.length > 2) {
          return {
            isMalicious: true,
            threatName: 'Suspicious Executable',
            filePath,
            indicators: suspiciousImports
          };
        }
      }
    }

    return { isMalicious: false };
  }

  // Verificar consistencia de tipo MIME
  checkMimeTypeConsistency(filePath) {
    const extension = path.extname(filePath).toLowerCase();
    const fileContent = fs.readFileSync(filePath);
    
    // Detección de archivos disfrazados
    if (extension === '.exe' && fileContent.slice(0, 4).toString() === '%PDF') {
      return {
        isMalicious: true,
        threatName: 'Disguised Executable (PDF)',
        filePath
      };
    }

    if (extension === '.pdf' && fileContent.slice(0, 2).toString() === 'MZ') {
      return {
        isMalicious: true,
        threatName: 'Disguised PDF (Executable)',
        filePath
      };
    }

    return { isMalicious: false };
  }

  // Escanear directorio completo
  async scanDirectory(dirPath) {
    try {
      const files = await fs.promises.readdir(dirPath);
      this.totalFiles = files.length;
      this.scannedFiles = 0;
      this.threatsFound = [];
      
      const results = [];
      
      for (const file of files) {
        const fullPath = path.join(dirPath, file);
        const stats = await fs.promises.stat(fullPath);
        
        if (stats.isDirectory()) {
          const subDirResults = await this.scanDirectory(fullPath);
          results.push(...subDirResults);
        } else {
          const scanResult = await this.scanFile(fullPath);
          this.scannedFiles++;
          this.scanProgress = Math.floor((this.scannedFiles / this.totalFiles) * 100);
          
          if (scanResult.isMalicious) {
            this.threatsFound.push(scanResult);
            await this.quarantineFile(fullPath);
          }
          
          results.push(scanResult);
        }
      }
      
      return results;
    } catch (error) {
      console.error(`Error scanning directory ${dirPath}:`, error);
      return [];
    }
  }

  // Poner archivo en cuarentena
  async quarantineFile(filePath) {
    try {
      const fileName = path.basename(filePath);
      const quarantinePath = path.join(this.quarantineDir, `${Date.now()}-${fileName}`);
      
      await fs.promises.copyFile(filePath, quarantinePath);
      await fs.promises.unlink(filePath);
      
      // Registrar metadatos
      const metaData = {
        originalPath: filePath,
        quarantineDate: new Date().toISOString(),
        fileHash: await this.calculateFileHash(quarantinePath)
      };
      
      await fs.promises.writeFile(
        `${quarantinePath}.meta`,
        JSON.stringify(metaData, null, 2)
      );
      
      return true;
    } catch (error) {
      console.error(`Error quarantining file ${filePath}:`, error);
      return false;
    }
  }

  // Instalar dependencias necesarias
  async installDependencies() {
    const dependencies = [
      'clamav', // Motor antivirus open-source
      'yara',   // Herramienta de identificación de malware
      'ssdeep'  // Fuzzy hashing para detección de variantes
    ];
    
    const installPromises = dependencies.map(dep => {
      return new Promise((resolve, reject) => {
        let command;
        let args;
        
        if (os.platform() === 'win32') {
          command = 'choco';
          args = ['install', dep, '-y'];
        } else {
          command = 'sudo';
          args = ['apt-get', 'install', '-y', dep];
        }
        
        const child = child_process.spawn(command, args);
        
        child.on('close', (code) => {
          if (code === 0) {
            resolve(`${dep} installed successfully`);
          } else {
            reject(`Failed to install ${dep}`);
          }
        });
      });
    });
    
    try {
      const results = await Promise.all(installPromises);
      return { success: true, results };
    } catch (error) {
      return { success: false, error };
    }
  }
}

// Endpoints de la API
const analyzer = new AdvancedFileAnalyzer();

// Ruta para obtener progreso del escaneo
app.get('/api/scan/progress', (req, res) => {
  res.json({
    progress: analyzer.scanProgress,
    scannedFiles: analyzer.scannedFiles,
    totalFiles: analyzer.totalFiles,
    threatsFound: analyzer.threatsFound.length
  });
});

// Ruta para escanear un archivo subido
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const result = await analyzer.scanFile(req.file.path);
    
    if (result.isMalicious) {
      await analyzer.quarantineFile(req.file.path);
      res.json({
        status: 'malicious',
        threat: result.threatName,
        file: req.file.originalname,
        details: result
      });
    } else {
      res.json({
        status: 'clean',
        file: req.file.originalname,
        details: result
      });
    }
    
    // Limpiar archivo temporal
    fs.unlink(req.file.path, () => {});
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Ruta para escanear un directorio
app.post('/api/scan/directory', async (req, res) => {
  try {
    const { dirPath } = req.body;
    
    if (!dirPath || !fs.existsSync(dirPath)) {
      return res.status(400).json({ error: 'Invalid directory path' });
    }
    
    // Iniciar escaneo en segundo plano
    analyzer.scanDirectory(dirPath)
      .then(results => {
        console.log('Scan completed:', results);
      })
      .catch(error => {
        console.error('Scan error:', error);
      });
    
    res.json({ 
      status: 'started',
      message: 'Scan started in background. Check progress at /api/scan/progress'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Ruta para instalar dependencias
app.post('/api/install-dependencies', async (req, res) => {
  try {
    const result = await analyzer.installDependencies();
    
    if (result.success) {
      res.json({ 
        status: 'success',
        message: 'Dependencies installed successfully',
        details: result.results
      });
    } else {
      res.status(500).json({ 
        status: 'error',
        error: result.error
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Ruta para obtener resultados de amenazas
app.get('/api/threats', (req, res) => {
  res.json({
    count: analyzer.threatsFound.length,
    threats: analyzer.threatsFound
  });
});

// Servir interfaz web
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('API Endpoints:');
  console.log(`- POST /api/scan/file - Scan uploaded file`);
  console.log(`- POST /api/scan/directory - Scan directory (provide path in body)`);
  console.log(`- GET /api/scan/progress - Get scan progress`);
  console.log(`- GET /api/threats - Get detected threats`);
  console.log(`- POST /api/install-dependencies - Install required dependencies`);
});
