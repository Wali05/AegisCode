// test-api.js
const testUrl = "https://github.com/facebook/react/blob/main/README.md";

async function runTest() {
    console.log("🚀 Firing request to local AegisCode Swarm...");
    const startTime = Date.now();

    try {
        const response = await fetch("http://localhost:3000/api/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ githubUrl: testUrl }),
        });

        const data = await response.json();
        const timeTaken = ((Date.now() - startTime) / 1000).toFixed(2);

        console.log(`\n⏱️ Swarm completed in ${timeTaken} seconds.\n`);
        console.log("📦 Output:", JSON.stringify(data, null, 2));

    } catch (error) {
        console.error("❌ Test failed:", error);
    }
}

runTest();