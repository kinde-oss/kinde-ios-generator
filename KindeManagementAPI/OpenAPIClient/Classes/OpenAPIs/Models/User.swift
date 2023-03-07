//
// User.swift
//
// Generated by openapi-generator
// https://openapi-generator.tech
//

import Foundation


public struct User: Codable, JSONEncodable, Hashable {

    public private(set) var id: Int?
    public private(set) var email: String?
    public private(set) var fullName: String?
    public private(set) var lastName: String?
    public private(set) var firstName: String?
    public private(set) var isSuspended: Bool?

    public init(id: Int? = nil, email: String? = nil, fullName: String? = nil, lastName: String? = nil, firstName: String? = nil, isSuspended: Bool? = nil) {
        self.id = id
        self.email = email
        self.fullName = fullName
        self.lastName = lastName
        self.firstName = firstName
        self.isSuspended = isSuspended
    }

    public enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case email
        case fullName = "full_name"
        case lastName = "last_name"
        case firstName = "first_name"
        case isSuspended = "is_suspended"
    }

    // Encodable protocol methods

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(id, forKey: .id)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(fullName, forKey: .fullName)
        try container.encodeIfPresent(lastName, forKey: .lastName)
        try container.encodeIfPresent(firstName, forKey: .firstName)
        try container.encodeIfPresent(isSuspended, forKey: .isSuspended)
    }
}

