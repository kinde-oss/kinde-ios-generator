import XCTest
@testable import KindeSDK

final class ClaimsSpec: XCTestCase {
    
    var auth: Auth!
    var claims: ClaimsService!
    var mockAuthStateRepository: MockAuthStateRepository!
    var mockLogger: MockLogger!
    
    override func setUp() {
        super.setUp()
        mockAuthStateRepository = MockAuthStateRepository()
        mockLogger = MockLogger()
        
        let config = Config(
            issuer: "https://test.kinde.com",
            clientId: "test_client_id",
            redirectUri: "https://test.com/callback",
            postLogoutRedirectUri: "https://test.com/logout",
            scope: "openid profile email",
            audience: nil
        )
        
        auth = Auth(config: config, authStateRepository: mockAuthStateRepository, logger: mockLogger)
        claims = auth.claims
    }
    
    override func tearDown() {
        auth = nil
        claims = nil
        mockAuthStateRepository = nil
        mockLogger = nil
        super.tearDown()
    }
    
    // MARK: - Test Claim Model
    
    func testClaimInitialization() {
        let claim = Claim(name: "test_claim", value: "test_value")
        XCTAssertEqual(claim.name, "test_claim")
        XCTAssertEqual(claim.value as? String, "test_value")
    }
    
    func testClaimWithNilValue() {
        let claim = Claim(name: "test_claim", value: nil)
        XCTAssertEqual(claim.name, "test_claim")
        XCTAssertNil(claim.value)
    }
    
    // MARK: - Test Claims Model
    
    func testClaimsInitialization() {
        let claimsDict = ["claim1": "value1", "claim2": "value2"]
        let claims = Claims(claims: claimsDict)
        XCTAssertEqual(claims.count, 2)
        XCTAssertEqual(claims.getClaimNames().count, 2)
    }
    
    func testGetClaim() {
        let claimsDict = ["claim1": "value1", "claim2": "value2"]
        let claims = Claims(claims: claimsDict)
        
        let claim1 = claims.getClaim(name: "claim1")
        XCTAssertNotNil(claim1)
        XCTAssertEqual(claim1?.name, "claim1")
        XCTAssertEqual(claim1?.value as? String, "value1")
        
        let claim3 = claims.getClaim(name: "claim3")
        XCTAssertNil(claim3)
    }
    
    func testHasClaim() {
        let claimsDict = ["claim1": "value1", "claim2": "value2"]
        let claims = Claims(claims: claimsDict)
        
        XCTAssertTrue(claims.hasClaim(name: "claim1"))
        XCTAssertTrue(claims.hasClaim(name: "claim2"))
        XCTAssertFalse(claims.hasClaim(name: "claim3"))
    }
    
    // MARK: - Test Claims Service - Not Authenticated
    
    func testGetClaimWhenNotAuthenticated() {
        mockAuthStateRepository.mockState = nil
        
        let claim = claims.getClaim(claimName: "test_claim")
        XCTAssertNil(claim)
    }
    
    func testGetAllClaimsWhenNotAuthenticated() {
        mockAuthStateRepository.mockState = nil
        
        let allClaims = claims.getAllClaims()
        XCTAssertEqual(allClaims.count, 0)
    }
    
    // MARK: - Test Claims Service - Authenticated
    
    func testGetClaimWhenAuthenticated() {
        setupMockAuthState()
        
        let claim = claims.getClaim(claimName: "aud")
        XCTAssertNotNil(claim)
        XCTAssertEqual(claim?.name, "aud")
        XCTAssertEqual(claim?.value as? [String], ["api.yourapp.com"])
    }
    
    func testGetClaimWithTokenType() {
        setupMockAuthState()
        
        let accessTokenClaim = claims.getClaim(claimName: "aud", tokenType: .accessToken)
        XCTAssertNotNil(accessTokenClaim)
        XCTAssertEqual(accessTokenClaim?.name, "aud")
        
        let idTokenClaim = claims.getClaim(claimName: "given_name", tokenType: .idToken)
        XCTAssertNotNil(idTokenClaim)
        XCTAssertEqual(idTokenClaim?.name, "given_name")
        XCTAssertEqual(idTokenClaim?.value as? String, "John")
    }
    
    func testGetAllClaimsWhenAuthenticated() {
        setupMockAuthState()
        
        let allClaims = claims.getAllClaims(tokenType: .accessToken)
        XCTAssertGreaterThan(allClaims.count, 0)
        XCTAssertTrue(allClaims.hasClaim(name: "aud"))
        XCTAssertTrue(allClaims.hasClaim(name: "iss"))
    }
    
    func testGetClaimWithClaimKey() {
        setupMockAuthState()
        
        let claim = claims.getClaim(claimKey: .audience)
        XCTAssertNotNil(claim)
        XCTAssertEqual(claim?.name, "aud")
        XCTAssertEqual(claim?.value as? [String], ["api.yourapp.com"])
    }
    
    // MARK: - Test Convenience Methods
    
    func testGetUserInfo() {
        setupMockAuthState()
        
        let userInfo = claims.getUserInfo()
        XCTAssertNotNil(userInfo["email"])
        XCTAssertNotNil(userInfo["given_name"])
        XCTAssertNotNil(userInfo["family_name"])
    }
    
    func testGetOrganizationInfo() {
        setupMockAuthState()
        
        let orgInfo = claims.getOrganizationInfo()
        XCTAssertNotNil(orgInfo["org_code"])
        XCTAssertNotNil(orgInfo["org_name"])
    }
    
    func testGetTokenValidationInfo() {
        setupMockAuthState()
        
        let validationInfo = claims.getTokenValidationInfo()
        XCTAssertNotNil(validationInfo["aud"])
        XCTAssertNotNil(validationInfo["iss"])
        XCTAssertNotNil(validationInfo["exp"])
    }
    
    func testGetCustomClaims() {
        setupMockAuthState()
        
        let customClaims = claims.getCustomClaims()
        XCTAssertNotNil(customClaims["custom:role"])
        XCTAssertEqual(customClaims["custom:role"] as? String, "admin")
    }
    
    func testGetCustomClaim() {
        setupMockAuthState()
        
        let customClaim = claims.getCustomClaim(claimName: "role")
        XCTAssertNotNil(customClaim)
        XCTAssertEqual(customClaim?.name, "custom:role")
        XCTAssertEqual(customClaim?.value as? String, "admin")
    }
    
    // MARK: - Test Individual Convenience Methods
    
    func testGetEmail() {
        setupMockAuthState()
        
        let email = claims.getEmail()
        XCTAssertEqual(email, "john.doe@example.com")
    }
    
    func testGetGivenName() {
        setupMockAuthState()
        
        let givenName = claims.getGivenName()
        XCTAssertEqual(givenName, "John")
    }
    
    func testGetFamilyName() {
        setupMockAuthState()
        
        let familyName = claims.getFamilyName()
        XCTAssertEqual(familyName, "Doe")
    }
    
    func testGetFullName() {
        setupMockAuthState()
        
        let fullName = claims.getFullName()
        XCTAssertEqual(fullName, "John Doe")
    }
    
    func testGetPicture() {
        setupMockAuthState()
        
        let picture = claims.getPicture()
        XCTAssertEqual(picture, "https://example.com/picture.jpg")
    }
    
    func testGetOrganizationCode() {
        setupMockAuthState()
        
        let orgCode = claims.getOrganizationCode()
        XCTAssertEqual(orgCode, "org_123")
    }
    
    func testGetOrganizationName() {
        setupMockAuthState()
        
        let orgName = claims.getOrganizationName()
        XCTAssertEqual(orgName, "Test Organization")
    }
    
    func testGetAudience() {
        setupMockAuthState()
        
        let audience = claims.getAudience()
        XCTAssertEqual(audience, ["api.yourapp.com"])
    }
    
    func testGetIssuer() {
        setupMockAuthState()
        
        let issuer = claims.getIssuer()
        XCTAssertEqual(issuer, "https://test.kinde.com")
    }
    
    func testGetExpirationTime() {
        setupMockAuthState()
        
        let expirationTime = claims.getExpirationTime()
        XCTAssertNotNil(expirationTime)
        XCTAssertTrue(expirationTime! > Date())
    }
    
    func testIsTokenExpired() {
        setupMockAuthState()
        
        let isExpired = claims.isTokenExpired()
        XCTAssertFalse(isExpired)
    }
    
    // MARK: - Test Has Claim Methods
    
    func testHasClaimWithName() {
        setupMockAuthState()
        
        XCTAssertTrue(claims.hasClaim(claimName: "aud"))
        XCTAssertTrue(claims.hasClaim(claimName: "given_name", tokenType: .idToken))
        XCTAssertFalse(claims.hasClaim(claimName: "non_existent_claim"))
    }
    
    func testHasClaimWithClaimKey() {
        setupMockAuthState()
        
        XCTAssertTrue(claims.hasClaim(claimKey: .audience))
        XCTAssertTrue(claims.hasClaim(claimKey: .email, tokenType: .idToken))
        XCTAssertFalse(claims.hasClaim(claimKey: .customRole))
    }
    
    // MARK: - Test Hard Checks (Validation)
    
    
    func testEmptyClaimNameValidation() {
        setupMockAuthState()
        
        // Test with empty claim name
        let emptyClaim = claims.getClaim(claimName: "")
        XCTAssertNil(emptyClaim)
        
        // Test with whitespace-only claim name
        let whitespaceClaim = claims.getClaim(claimName: "   ")
        XCTAssertNil(whitespaceClaim)
        
        // Test hasClaim with empty claim name
        let hasEmptyClaim = claims.hasClaim(claimName: "")
        XCTAssertFalse(hasEmptyClaim)
        
        // Test getCustomClaim with empty claim name
        let emptyCustomClaim = claims.getCustomClaim(claimName: "")
        XCTAssertNil(emptyCustomClaim)
    }
    
    func testNoClaimsAvailableValidation() {
        // Test when no auth state is available
        mockAuthStateRepository.mockState = nil
        
        let allClaims = claims.getAllClaims()
        XCTAssertEqual(allClaims.count, 0)
        
        let claim = claims.getClaim(claimName: "aud")
        XCTAssertNil(claim)
    }
    
    // MARK: - Helper Methods
    
    private func setupMockAuthState() {
        let accessTokenClaims = [
            "aud": ["api.yourapp.com"],
            "iss": "https://test.kinde.com",
            "sub": "user_123",
            "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
            "iat": Date().timeIntervalSince1970,
            "org_code": "org_123",
            "org_name": "Test Organization",
            "custom:role": "admin"
        ]
        
        let idTokenClaims = [
            "sub": "user_123",
            "email": "john.doe@example.com",
            "given_name": "John",
            "family_name": "Doe",
            "name": "John Doe",
            "picture": "https://example.com/picture.jpg",
            "email_verified": true
        ]
        
        mockAuthStateRepository.setupMockState(
            accessTokenClaims: accessTokenClaims,
            idTokenClaims: idTokenClaims
        )
    }
}

// MARK: - Mock Classes

class MockAuthStateRepository: AuthStateRepository {
    var mockState: OIDAuthState?
    
    override var state: OIDAuthState? {
        return mockState
    }
    
    func setupMockState(accessTokenClaims: [String: Any], idTokenClaims: [String: Any]) {
        let mockTokenResponse = MockTokenResponse(
            accessTokenClaims: accessTokenClaims,
            idTokenClaims: idTokenClaims
        )
        
        let mockAuthState = MockAuthState(tokenResponse: mockTokenResponse)
        mockState = mockAuthState
    }
}

class MockAuthState: OIDAuthState {
    private let mockTokenResponse: MockTokenResponse
    
    init(tokenResponse: MockTokenResponse) {
        self.mockTokenResponse = tokenResponse
        super.init()
    }
    
    override var isAuthorized: Bool {
        return true
    }
    
    override var lastTokenResponse: OIDTokenResponse? {
        return mockTokenResponse
    }
}

class MockTokenResponse: OIDTokenResponse {
    private let accessTokenClaims: [String: Any]
    private let idTokenClaims: [String: Any]
    
    init(accessTokenClaims: [String: Any], idTokenClaims: [String: Any]) {
        self.accessTokenClaims = accessTokenClaims
        self.idTokenClaims = idTokenClaims
        super.init()
    }
    
    override var accessToken: String? {
        return "mock_access_token"
    }
    
    override var idToken: String? {
        return "mock_id_token"
    }
    
    override var accessTokenExpirationDate: Date? {
        return Date().addingTimeInterval(3600)
    }
}

// Extension to add parsedJWT property to mock tokens
extension String {
    var parsedJWT: [String: Any] {
        // Return mock claims based on token type
        if self == "mock_access_token" {
            return [
                "aud": ["api.yourapp.com"],
                "iss": "https://test.kinde.com",
                "sub": "user_123",
                "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
                "iat": Date().timeIntervalSince1970,
                "org_code": "org_123",
                "org_name": "Test Organization",
                "custom:role": "admin"
            ]
        } else if self == "mock_id_token" {
            return [
                "sub": "user_123",
                "email": "john.doe@example.com",
                "given_name": "John",
                "family_name": "Doe",
                "name": "John Doe",
                "picture": "https://example.com/picture.jpg",
                "email_verified": true
            ]
        }
        return [:]
    }
}

class MockLogger: LoggerProtocol {
    var debugMessages: [String] = []
    var errorMessages: [String] = []
    
    func debug(message: String) {
        debugMessages.append(message)
    }
    
    func error(message: String) {
        errorMessages.append(message)
    }
}
