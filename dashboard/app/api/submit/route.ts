import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, companySize, usesMicrosoft365, biggestConcern } = body ?? {};

    if (!email || !companySize || !usesMicrosoft365 || !biggestConcern) {
      return NextResponse.json({ error: "All fields are required." }, { status: 400 });
    }

    console.info("Cloud Locksmith contact form submission", {
      email,
      companySize,
      usesMicrosoft365,
      biggestConcern,
      receivedAt: new Date().toISOString(),
    });

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    console.error("Contact form submission error", error);
    return NextResponse.json({ error: "Internal server error." }, { status: 500 });
  }
}
