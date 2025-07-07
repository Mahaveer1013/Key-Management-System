#!/usr/bin/env node

/**
 * Secure Document Manager for KMS
 * Handles encryption, storage, and retrieval of sensitive user documents
 * Supports: Aadhar Card, PAN Card, Passport, Driving License, etc.
 */

const axios = require('axios');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    // Service URLs
    KEY_SERVER_URL: 'http://localhost:8000',
    MASTER_KEY_SERVER_URL: 'http://localhost:8001',
    AUTH_SERVER_URL: 'http://localhost:8002',

    // Database config
    DB_CONFIG: {
        host: '127.0.0.1',
        user: 'root',
        password: 'root',
        database: 'kms',
        port: 3306
    },

    // Document types
    DOCUMENT_TYPES: {
        AADHAR_CARD: 'aadhar_card',
        PAN_CARD: 'pan_card',
        PASSPORT: 'passport',
        DRIVING_LICENSE: 'driving_license',
        VOTER_ID: 'voter_id',
        BANK_PASSBOOK: 'bank_passbook',
        INSURANCE_POLICY: 'insurance_policy',
        MEDICAL_RECORDS: 'medical_records',
        TAX_DOCUMENTS: 'tax_documents',
        PROPERTY_DOCUMENTS: 'property_documents'
    },

    // Encryption settings
    ENCRYPTION_ALGORITHM: 'aes-256-gcm',
    IV_LENGTH: 16,
    TAG_LENGTH: 16
};

class SecureDocumentManager {
    constructor() {
        this.dbPool = null;
        this.userTokens = new Map(); // Cache for user tokens
    }

    async init() {
        try {
            // Initialize database connection
            this.dbPool = mysql.createPool({
                ...CONFIG.DB_CONFIG,
                connectionLimit: 10,
                acquireTimeout: 60000,
                timeout: 60000
            });

            // Test connection
            const connection = await this.dbPool.getConnection();
            await connection.ping();
            connection.release();

            // Create tables if they don't exist
            await this.createTables();

            console.log('✅ Secure Document Manager initialized successfully');
        } catch (error) {
            console.error('❌ Failed to initialize Secure Document Manager:', error.message);
            throw error;
        }
    }

    async createTables() {
        const connection = await this.dbPool.getConnection();

        try {
            // Users table
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    phone VARCHAR(20),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            `);

            // Documents table
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS user_documents (
                    id VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    document_type ENUM('aadhar_card', 'pan_card', 'passport', 'driving_license', 'voter_id', 'bank_passbook', 'insurance_policy', 'medical_records', 'tax_documents', 'property_documents') NOT NULL,
                    document_name VARCHAR(255) NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    encrypted_dek TEXT NOT NULL,
                    metadata JSON,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_user_documents (user_id, document_type)
                )
            `);

            // Document versions table for audit trail
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS document_versions (
                    id VARCHAR(64) PRIMARY KEY,
                    document_id VARCHAR(64) NOT NULL,
                    version_number INT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    encrypted_dek TEXT NOT NULL,
                    change_reason VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (document_id) REFERENCES user_documents(id) ON DELETE CASCADE,
                    INDEX idx_document_versions (document_id, version_number)
                )
            `);

            console.log('✅ Database tables created/verified');
        } finally {
            connection.release();
        }
    }

    // Generate unique IDs
    generateId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Get or create user token
    async getUserToken(userId) {
        if (this.userTokens.has(userId)) {
            return this.userTokens.get(userId);
        }

        try {
            // Create a new key for the user
            const response = await axios.post(`${CONFIG.KEY_SERVER_URL}/api/keys`, {
                user_id: userId,
                data: crypto.randomBytes(100).toString('base64')
            });

            const token = response.data.access_token;
            this.userTokens.set(userId, token);
            return token;
        } catch (error) {
            console.error(`Failed to get token for user ${userId}:`, error.message);
            throw error;
        }
    }

    // Encrypt document data
    async encryptDocument(documentData, dek) {
        try {
            const dekBuffer = Buffer.from(dek, 'hex');
            const dataBuffer = Buffer.from(JSON.stringify(documentData), 'utf8');

            // Generate IV and encrypt
            const iv = crypto.randomBytes(CONFIG.IV_LENGTH);
            const cipher = crypto.createCipheriv(CONFIG.ENCRYPTION_ALGORITHM, dekBuffer, iv);

            let encrypted = cipher.update(dataBuffer);
            encrypted = Buffer.concat([encrypted, cipher.final()]);

            // Get auth tag for GCM
            const authTag = cipher.getAuthTag();

            // Combine IV + Auth Tag + Encrypted Data
            const result = Buffer.concat([iv, authTag, encrypted]);
            return result.toString('base64');
        } catch (error) {
            console.error('Encryption failed:', error.message);
            throw error;
        }
    }

    // Decrypt document data
    async decryptDocument(encryptedData, dek) {
        try {
            const dekBuffer = Buffer.from(dek, 'hex');
            const encryptedBuffer = Buffer.from(encryptedData, 'base64');

            // Extract IV, Auth Tag, and Encrypted Data
            const iv = encryptedBuffer.slice(0, CONFIG.IV_LENGTH);
            const authTag = encryptedBuffer.slice(CONFIG.IV_LENGTH, CONFIG.IV_LENGTH + CONFIG.TAG_LENGTH);
            const ciphertext = encryptedBuffer.slice(CONFIG.IV_LENGTH + CONFIG.TAG_LENGTH);

            // Decrypt
            const decipher = crypto.createDecipheriv(CONFIG.ENCRYPTION_ALGORITHM, dekBuffer, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            return JSON.parse(decrypted.toString('utf8'));
        } catch (error) {
            console.error('Decryption failed:', error.message);
            throw error;
        }
    }

    // Store document securely
    async storeDocument(userId, documentType, documentData, metadata = {}) {
        try {
            console.log(`📄 Storing ${documentType} for user ${userId}...`);

            // Get user token
            const token = await this.getUserToken(userId);

            // Generate document ID
            const documentId = this.generateId();

            // Encrypt document data
            const dek = crypto.randomBytes(32).toString('hex');
            const encryptedData = await this.encryptDocument(documentData, dek);

            // Encrypt DEK with master key
            const masterKeyResponse = await axios.post(`${CONFIG.MASTER_KEY_SERVER_URL}/api/encrypt`, {
                data: Buffer.from(JSON.stringify(documentData)).toString('base64'),
                dek: dek
            });

            const encryptedDek = masterKeyResponse.data.encrypted_dek;

            // Store in database
            const connection = await this.dbPool.getConnection();
            try {
                // Ensure user exists
                await connection.execute(
                    'INSERT IGNORE INTO users (id, name, email, phone) VALUES (?, ?, ?, ?)',
                    [userId, metadata.name || 'Unknown', metadata.email || null, metadata.phone || null]
                );

                // Store document
                await connection.execute(
                    `INSERT INTO user_documents (id, user_id, document_type, document_name, encrypted_data, encrypted_dek, metadata)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [documentId, userId, documentType, metadata.documentName || documentType, encryptedData, encryptedDek, JSON.stringify(metadata)]
                );

                console.log(`✅ Document stored successfully with ID: ${documentId}`);
                return {
                    documentId,
                    userId,
                    documentType,
                    status: 'stored',
                    timestamp: new Date().toISOString()
                };
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to store document: ${error.message}`);
            throw error;
        }
    }

    // Retrieve document securely
    async retrieveDocument(userId, documentId) {
        try {
            console.log(`🔍 Retrieving document ${documentId} for user ${userId}...`);

            // Get user token
            const token = await this.getUserToken(userId);

            // Retrieve from database
            const connection = await this.dbPool.getConnection();
            let document;
            try {
                const [rows] = await connection.execute(
                    'SELECT * FROM user_documents WHERE id = ? AND user_id = ?',
                    [documentId, userId]
                );

                if (rows.length === 0) {
                    throw new Error('Document not found or access denied');
                }

                document = rows[0];
            } finally {
                connection.release();
            }

            // Decrypt DEK using master key
            const dekResponse = await axios.post(`${CONFIG.MASTER_KEY_SERVER_URL}/api/decrypt-dek`, {
                encrypted_dek: document.encrypted_dek
            }, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const dek = dekResponse.data.dek;

            // Decrypt document data
            const decryptedData = await this.decryptDocument(document.encrypted_data, dek);

            console.log(`✅ Document retrieved successfully`);
            return {
                documentId: document.id,
                userId: document.user_id,
                documentType: document.document_type,
                documentName: document.document_name,
                data: decryptedData,
                metadata: JSON.parse(document.metadata || '{}'),
                createdAt: document.created_at,
                updatedAt: document.updated_at
            };
        } catch (error) {
            console.error(`❌ Failed to retrieve document: ${error.message}`);
            throw error;
        }
    }

    // List user documents
    async listUserDocuments(userId) {
        try {
            const connection = await this.dbPool.getConnection();
            try {
                const [rows] = await connection.execute(
                    'SELECT id, document_type, document_name, created_at, updated_at, metadata FROM user_documents WHERE user_id = ? ORDER BY created_at DESC',
                    [userId]
                );

                return rows.map(row => ({
                    documentId: row.id,
                    documentType: row.document_type,
                    documentName: row.document_name,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    metadata: JSON.parse(row.metadata || '{}')
                }));
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to list documents: ${error.message}`);
            throw error;
        }
    }

    // Update document
    async updateDocument(userId, documentId, newData, metadata = {}) {
        try {
            console.log(`🔄 Updating document ${documentId} for user ${userId}...`);

            // Get current document
            const currentDoc = await this.retrieveDocument(userId, documentId);

            // Create version backup
            const connection = await this.dbPool.getConnection();
            try {
                // Get current version number
                const [versionRows] = await connection.execute(
                    'SELECT MAX(version_number) as max_version FROM document_versions WHERE document_id = ?',
                    [documentId]
                );
                const nextVersion = (versionRows[0].max_version || 0) + 1;

                // Store current version
                await connection.execute(
                    'INSERT INTO document_versions (id, document_id, version_number, encrypted_data, encrypted_dek, change_reason) VALUES (?, ?, ?, ?, ?, ?)',
                    [this.generateId(), documentId, nextVersion, currentDoc.encrypted_data, currentDoc.encrypted_dek, metadata.changeReason || 'Update']
                );

                // Update document
                const token = await this.getUserToken(userId);
                const dek = crypto.randomBytes(32).toString('hex');
                const encryptedData = await this.encryptDocument(newData, dek);

                const masterKeyResponse = await axios.post(`${CONFIG.MASTER_KEY_SERVER_URL}/api/encrypt`, {
                    data: Buffer.from(JSON.stringify(newData)).toString('base64'),
                    dek: dek
                });

                const encryptedDek = masterKeyResponse.data.encrypted_dek;

                await connection.execute(
                    'UPDATE user_documents SET encrypted_data = ?, encrypted_dek = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                    [encryptedData, encryptedDek, JSON.stringify(metadata), documentId, userId]
                );

                console.log(`✅ Document updated successfully`);
                return {
                    documentId,
                    userId,
                    status: 'updated',
                    version: nextVersion,
                    timestamp: new Date().toISOString()
                };
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to update document: ${error.message}`);
            throw error;
        }
    }

    // Delete document
    async deleteDocument(userId, documentId) {
        try {
            console.log(`🗑️  Deleting document ${documentId} for user ${userId}...`);

            const connection = await this.dbPool.getConnection();
            try {
                const [result] = await connection.execute(
                    'DELETE FROM user_documents WHERE id = ? AND user_id = ?',
                    [documentId, userId]
                );

                if (result.affectedRows === 0) {
                    throw new Error('Document not found or access denied');
                }

                console.log(`✅ Document deleted successfully`);
                return {
                    documentId,
                    userId,
                    status: 'deleted',
                    timestamp: new Date().toISOString()
                };
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to delete document: ${error.message}`);
            throw error;
        }
    }

    // Search documents by type
    async searchDocuments(userId, documentType) {
        try {
            const connection = await this.dbPool.getConnection();
            try {
                const [rows] = await connection.execute(
                    'SELECT id, document_type, document_name, created_at, updated_at, metadata FROM user_documents WHERE user_id = ? AND document_type = ? ORDER BY created_at DESC',
                    [userId, documentType]
                );

                return rows.map(row => ({
                    documentId: row.id,
                    documentType: row.document_type,
                    documentName: row.document_name,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    metadata: JSON.parse(row.metadata || '{}')
                }));
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to search documents: ${error.message}`);
            throw error;
        }
    }

    // Get document version history
    async getDocumentHistory(userId, documentId) {
        try {
            const connection = await this.dbPool.getConnection();
            try {
                const [rows] = await connection.execute(
                    'SELECT version_number, change_reason, created_at FROM document_versions WHERE document_id = ? ORDER BY version_number DESC',
                    [documentId]
                );

                return rows.map(row => ({
                    version: row.version_number,
                    changeReason: row.change_reason,
                    timestamp: row.created_at
                }));
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error(`❌ Failed to get document history: ${error.message}`);
            throw error;
        }
    }

    // Cleanup
    async cleanup() {
        if (this.dbPool) {
            await this.dbPool.end();
        }
        console.log('🧹 Cleanup completed');
    }
}

// Example usage and testing
async function runExample() {
    const manager = new SecureDocumentManager();

    try {
        await manager.init();

        const userId = 'user-123';

        // Example 1: Store Aadhar Card
        console.log('\n📋 Example 1: Storing Aadhar Card');
        const aadharData = {
            aadharNumber: '1234-5678-9012',
            name: 'John Doe',
            dateOfBirth: '1990-01-01',
            gender: 'Male',
            address: '123 Main Street, City, State, PIN',
            photo: 'base64-encoded-photo-data',
            issueDate: '2020-01-01',
            validUntil: '2030-01-01'
        };

        const aadharResult = await manager.storeDocument(userId, CONFIG.DOCUMENT_TYPES.AADHAR_CARD, aadharData, {
            documentName: 'Aadhar Card - John Doe',
            name: 'John Doe',
            email: 'john.doe@example.com',
            phone: '+91-9876543210'
        });

        // Example 2: Store PAN Card
        console.log('\n📋 Example 2: Storing PAN Card');
        const panData = {
            panNumber: 'ABCDE1234F',
            name: 'JOHN DOE',
            fatherName: 'FATHER DOE',
            dateOfBirth: '1990-01-01',
            issueDate: '2015-01-01',
            validUntil: '2030-01-01',
            photo: 'base64-encoded-photo-data'
        };

        const panResult = await manager.storeDocument(userId, CONFIG.DOCUMENT_TYPES.PAN_CARD, panData, {
            documentName: 'PAN Card - John Doe',
            name: 'John Doe',
            email: 'john.doe@example.com'
        });

        // Example 3: List all documents
        console.log('\n📋 Example 3: Listing all documents');
        const documents = await manager.listUserDocuments(userId);
        console.log('User documents:', documents);

        // Example 4: Retrieve Aadhar Card
        console.log('\n📋 Example 4: Retrieving Aadhar Card');
        const retrievedAadhar = await manager.retrieveDocument(userId, aadharResult.documentId);
        console.log('Retrieved Aadhar:', {
            documentId: retrievedAadhar.documentId,
            documentType: retrievedAadhar.documentType,
            name: retrievedAadhar.data.name,
            aadharNumber: retrievedAadhar.data.aadharNumber
        });

        // Example 5: Update document
        console.log('\n📋 Example 5: Updating document');
        const updatedAadharData = { ...aadharData, address: '456 New Street, City, State, PIN' };
        const updateResult = await manager.updateDocument(userId, aadharResult.documentId, updatedAadharData, {
            changeReason: 'Address update',
            name: 'John Doe',
            email: 'john.doe@example.com'
        });

        // Example 6: Search documents by type
        console.log('\n📋 Example 6: Searching documents by type');
        const aadharDocuments = await manager.searchDocuments(userId, CONFIG.DOCUMENT_TYPES.AADHAR_CARD);
        console.log('Aadhar documents:', aadharDocuments);

        // Example 7: Get document history
        console.log('\n📋 Example 7: Getting document history');
        const history = await manager.getDocumentHistory(userId, aadharResult.documentId);
        console.log('Document history:', history);

        console.log('\n✅ All examples completed successfully!');

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    } finally {
        await manager.cleanup();
    }
}

// CLI interface
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log('🔐 Secure Document Manager for KMS');
        console.log('Usage: node secure-document-manager.js [command] [options]');
        console.log('\nCommands:');
        console.log('  example     - Run example usage');
        console.log('  store       - Store a document');
        console.log('  retrieve    - Retrieve a document');
        console.log('  list        - List user documents');
        console.log('  update      - Update a document');
        console.log('  delete      - Delete a document');
        console.log('  search      - Search documents by type');
        console.log('  history     - Get document history');
        return;
    }

    const command = args[0];
    const manager = new SecureDocumentManager();

    try {
        await manager.init();

        switch (command) {
            case 'example':
                await runExample();
                break;
            case 'store':
                // Implementation for CLI store command
                console.log('Store command - implement as needed');
                break;
            case 'retrieve':
                // Implementation for CLI retrieve command
                console.log('Retrieve command - implement as needed');
                break;
            default:
                console.log(`Unknown command: ${command}`);
        }
    } catch (error) {
        console.error('❌ Command failed:', error.message);
    } finally {
        await manager.cleanup();
    }
}

// Run if this file is executed directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = {
    SecureDocumentManager,
    CONFIG
};
