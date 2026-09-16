import 'package:flutter_test/flutter_test.dart';
import 'package:xenonypt/main.dart';

void main() {
  testWidgets('basic test', (WidgetTester tester) async {
    await tester.pumpWidget(const XenonyptApp());
    expect(find.byType(XenonyptApp), findsOneWidget);
  });
}
