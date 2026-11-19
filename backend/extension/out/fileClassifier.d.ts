/**
 * File Classifier — Maps file paths and VS Code languageIds to rule languages.
 *
 * Port of engine/file_classifier.py EXTENSION_TO_LANGUAGE mapping.
 * Also handles skip logic for node_modules, .git, dist, etc.
 */
/**
 * Classify a file to its rule language. Returns null if unsupported.
 * Uses both file extension and VS Code languageId for best accuracy.
 */
export declare function classifyLanguage(filePath: string, vscodeLangId?: string): string | null;
/**
 * Check if a file should be skipped (node_modules, binaries, etc.).
 */
export declare function shouldSkipFile(filePath: string): boolean;
