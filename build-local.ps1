param(
    [Parameter(Position = 100)]
    [string]$JdkPath = "D:/jdk/jdk-21.0.12.15",
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$GradleArguments = @("build")
)

$ErrorActionPreference = "Stop"
$javaPath = Join-Path -Path $JdkPath -ChildPath "bin/java.exe"
$compilerPath = Join-Path -Path $JdkPath -ChildPath "bin/javac.exe"
if (!(Test-Path -LiteralPath $compilerPath)) {
    throw "请通过 -JdkPath 指定包含 javac.exe 的 JDK 21 目录。"
}
Push-Location -LiteralPath $PSScriptRoot
try {
    & $javaPath "-Dorg.gradle.java.home=$JdkPath" "-Dorg.gradle.java.installations.paths=$JdkPath" -cp "gradle/wrapper/gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain @GradleArguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
