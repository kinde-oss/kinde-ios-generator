//
// Pagination.swift
//
// Kinde SDK Pagination Models
//

import Foundation

/// Pagination parameters for API requests
public struct PaginationParams: Codable {
    /// Number of results per page. Defaults to 10 if not specified
    public let pageSize: Int?
    /// Token to get the next page of results
    public let nextToken: String?
    
    public init(pageSize: Int? = nil, nextToken: String? = nil) {
        self.pageSize = pageSize
        self.nextToken = nextToken
    }
}

/// Paginated response containing data and pagination information
public struct PaginatedResponse<T: Codable>: Codable {
    /// The response code
    public let code: String?
    /// The response message
    public let message: String?
    /// The actual data items
    public let items: [T]
    /// Token to get the next page of results
    public let nextToken: String?
    
    public init(code: String? = nil, message: String? = nil, items: [T], nextToken: String? = nil) {
        self.code = code
        self.message = message
        self.items = items
        self.nextToken = nextToken
    }
    
    /// Check if there are more pages available
    public var hasNextPage: Bool {
        return nextToken != nil && !nextToken!.isEmpty
    }
}

/// Pagination result for async operations
public enum PaginationResult<T: Codable> {
    case success(PaginatedResponse<T>)
    case failure(Error)
}

/// Pagination helper for managing paginated requests
public class PaginationHelper<T: Codable> {
    private let requestHandler: (PaginationParams) async throws -> PaginatedResponse<T>
    private var currentToken: String?
    private let pageSize: Int?
    
    public init(pageSize: Int? = nil, requestHandler: @escaping (PaginationParams) async throws -> PaginatedResponse<T>) {
        self.pageSize = pageSize
        self.requestHandler = requestHandler
    }
    
    /// Get the first page of results
    public func getFirstPage() async throws -> PaginatedResponse<T> {
        let params = PaginationParams(pageSize: pageSize, nextToken: nil)
        let response = try await requestHandler(params)
        currentToken = response.nextToken
        return response
    }
    
    /// Get the next page of results
    public func getNextPage() async throws -> PaginatedResponse<T>? {
        guard let token = currentToken, !token.isEmpty else {
            return nil
        }
        
        let params = PaginationParams(pageSize: pageSize, nextToken: token)
        let response = try await requestHandler(params)
        currentToken = response.nextToken
        return response
    }
    
    /// Check if there are more pages available
    public var hasNextPage: Bool {
        return currentToken != nil && !currentToken!.isEmpty
    }
    
    /// Reset pagination to start from the beginning
    public func reset() {
        currentToken = nil
    }
    
    /// Get all pages of results (use with caution for large datasets)
    public func getAllPages() async throws -> [T] {
        var allItems: [T] = []
        
        let firstPage = try await getFirstPage()
        allItems.append(contentsOf: firstPage.items)
        
        while hasNextPage {
            if let nextPage = try await getNextPage() {
                allItems.append(contentsOf: nextPage.items)
            }
        }
        
        return allItems
    }
}
