// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "KindeSDK",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "KindeSDK",
            targets: ["KindeSDK"]
        ),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
	.package(url: "https://github.com/openid/AppAuth-iOS.git", from: "1.6.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "KindeSDK",
            dependencies: [
		.product(name: "AppAuth", package: "AppAuth-iOS")
		 ],
            path: "KindeSDK/"
        ),
    ]
)
